package daemon

import (
	"sync"
	"time"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/incident"
	csmlog "github.com/pidginhost/csm/internal/log"
	"github.com/pidginhost/csm/internal/metrics"
	"github.com/pidginhost/csm/internal/store"
)

var (
	incidentOnce            sync.Once
	incidentCorrelator      *incident.Correlator
	incidentRegistry        = metrics.Default
	incidentRetentionCancel func()
	incidentAutoCloseCancel func()

	// incidentSprayBlocker is the firewall hand-off the daemon wires in
	// before IncidentCorrelator() is first invoked. The closure forwards
	// to fwEngine.BlockIP, which already honors auto_response.dry_run via
	// SetDryRunEnabledFunc, so the callback does not need to re-check it.
	// nil means "no blocker wired" (early startup or unit tests); the
	// singleton then skips wiring OnSprayBlock and the spray detector
	// stays detection-only even with BlockAtSeverity set.
	incidentSprayBlocker func(ip, reason string, timeout time.Duration) error
)

// SetIncidentSprayBlocker installs the firewall-side hand-off used by the
// credential_spray super-incident path. Call once after the firewall
// engine is built and before the first IncidentCorrelator() call.
// Passing nil clears the binding.
func SetIncidentSprayBlocker(fn func(ip, reason string, timeout time.Duration) error) {
	incidentSprayBlocker = fn
}

// incidentAutoCloseInterval is how often the daemon scans Open / Contained
// incidents for staleness. One hour is fast enough that 24h-idle incidents
// close within ~25h worst-case, but slow enough that the per-kind walk
// stays cheap on hosts with thousands of incidents.
const incidentAutoCloseInterval = 1 * time.Hour

// incidentRetentionPeriod is how long resolved/dismissed incidents are
// kept before compaction prunes them. Named constant per project
// convention; config exposure deferred until operators ask.
const incidentRetentionPeriod = 30 * 24 * time.Hour

// incidentOpenThreshold is the number of correlated findings required
// before a non-Critical finding opens an incident. Two means an
// isolated probe (a single dictionary-attack guess, one modsec hit
// from a wandering scanner) is treated as a finding only and never
// promoted to an incident on its own; the next correlated event
// inside the merge window does the promotion. Declared as var so
// tests that exercise the correlator wiring (where one finding is
// expected to land in one incident immediately) can pin it to 1
// via resetIncidentForTest. Production code never mutates this.
var incidentOpenThreshold = 2

// IncidentCorrelator returns the daemon-wide incident correlator.
// On first call: builds the correlator, restores prior state from
// the bbolt store (when available), and registers metrics. Safe for
// concurrent callers.
func IncidentCorrelator() *incident.Correlator {
	incidentOnce.Do(func() {
		db := store.Global()
		var persist func(incident.Incident)
		if db != nil {
			persist = func(inc incident.Incident) {
				_ = db.SaveIncident(inc)
			}
		}
		// Resolve spray-suppression knobs from the active config. nil
		// config (early test wiring) leaves the detector disabled.
		var spray incident.SpraySuppressionConfig
		var whitelisted func(string) bool
		var onSprayBlock func(ip, reason string)
		if cfg := globalCfgForIncidents(); cfg != nil {
			spray = incident.SpraySuppressionConfig{
				Enabled:            cfg.Incidents.SpraySuppression.Enabled,
				DryRun:             cfg.Incidents.SpraySuppression.DryRun,
				DistinctMailboxes:  cfg.Incidents.SpraySuppression.DistinctMailboxes,
				SeverityEscalateAt: cfg.Incidents.SpraySuppression.SeverityEscalateAt,
				PerCheck:           cfg.IncidentsSpraySuppressionPerCheck(),
				MaxTrackedIPs:      cfg.Incidents.SpraySuppression.MaxTrackedIPs,
				BlockAtSeverity:    cfg.Incidents.SpraySuppression.BlockAtSeverity,
			}
			// Only wire the firewall hand-off when block-on-spray is
			// configured and the daemon has a blocker installed. The live
			// auto_response gate is checked at decision time so SIGHUP
			// changes to enabled/block_ips take effect without rebuilding
			// the singleton.
			if spray.BlockAtSeverity != "" && incidentSprayBlocker != nil {
				blocker := incidentSprayBlocker
				onSprayBlock = func(ip, reason string) {
					cfg := globalCfgForIncidents()
					if cfg == nil || !cfg.AutoResponse.Enabled || !cfg.AutoResponse.BlockIPs {
						return
					}
					timeout, perr := time.ParseDuration(cfg.AutoResponse.BlockExpiry)
					if perr != nil || timeout <= 0 {
						timeout = 24 * time.Hour
					}
					if err := blocker(ip, "CSM credential_spray: "+reason, timeout); err != nil {
						csmlog.Warn("credential_spray block failed", "ip", ip, "err", err)
					}
				}
			}
			// Whitelist accessor: prefer the bbolt-backed live whitelist
			// (operators add IPs at runtime), fall back to the static
			// reputation.whitelist list. db nil-check inside the closure
			// so the resolution stays current across daemon restarts.
			staticAllow := make(map[string]bool, len(cfg.Reputation.Whitelist))
			for _, ip := range cfg.Reputation.Whitelist {
				if ip != "" {
					staticAllow[ip] = true
				}
			}
			whitelisted = func(ip string) bool {
				if ip == "" {
					return false
				}
				if staticAllow[ip] {
					return true
				}
				if d := store.Global(); d != nil {
					return d.IsWhitelisted(ip)
				}
				return false
			}
		}
		incidentCorrelator = incident.NewCorrelator(incident.CorrelatorConfig{
			Persist:          persist,
			OpenThreshold:    incidentOpenThreshold,
			SpraySuppression: spray,
			IsWhitelisted:    whitelisted,
			CanSprayBlock: func() bool {
				cfg := globalCfgForIncidents()
				return cfg != nil && cfg.AutoResponse.Enabled && cfg.AutoResponse.BlockIPs
			},
			OnSprayBlock: onSprayBlock,
		})
		if db != nil {
			if list, err := db.ListIncidents(); err == nil {
				incidentCorrelator.Restore(list)
			}
		}
		incident.RegisterMetrics(incidentRegistry(), incidentCorrelator)
		incidentRetentionCancel = startIncidentRetentionLoop(incidentCorrelator)
		// Auto-close runs on its own hourly ticker so the daily retention
		// loop is not coupled to the close cadence; a 24h-idle incident
		// closes within at most ~25h.
		if cfg := globalCfgForIncidents(); cfg != nil {
			incidentAutoCloseCancel = startIncidentAutoCloseLoop(incidentCorrelator, cfg)
		}
	})
	return incidentCorrelator
}

// globalCfgForIncidents is overridden in tests to plug a synthetic config
// without touching package-level state. Production wiring sets this to a
// closure over the daemon's loaded config; until that wiring lands the
// auto-close loop simply does not start (no panic). The retention loop
// keeps running unchanged.
var globalCfgForIncidents = func() *config.Config { return nil }

// SetIncidentConfigSource wires the daemon-loaded config so the
// incident singleton can resolve auto-close thresholds at construction.
// Called once from cmd/csm/serve before IncidentCorrelator() is first
// invoked. Subsequent calls overwrite the source so reload paths can
// rebind without restarting the singleton.
func SetIncidentConfigSource(get func() *config.Config) {
	if get == nil {
		globalCfgForIncidents = func() *config.Config { return nil }
		return
	}
	globalCfgForIncidents = get
}

// startIncidentAutoCloseLoop launches the per-kind idle scan that
// auto-resolves stale incidents. Returns a cancel func. Logs every run
// at info when work was done; silent when nothing closed.
func startIncidentAutoCloseLoop(c *incident.Correlator, cfg *config.Config) func() {
	stop := make(chan struct{})
	go func() {
		t := time.NewTicker(incidentAutoCloseInterval)
		defer t.Stop()
		// First sweep fires after a 30-min warm-up so the daemon has
		// finished restoring incidents and processing any backlog from
		// the journal before we start writing back.
		first := time.NewTimer(30 * time.Minute)
		defer first.Stop()
		for {
			select {
			case <-stop:
				return
			case <-first.C:
				runIncidentAutoClose(c, cfg)
			case <-t.C:
				runIncidentAutoClose(c, cfg)
			}
		}
	}()
	return func() { close(stop) }
}

// runIncidentAutoClose is one tick of the auto-close loop. Gated on
// the operator's config and on the per-kind threshold map. dry_run=true
// only increments counters; live mode flips Status -> resolved and
// records "auto:stale" attribution.
func runIncidentAutoClose(c *incident.Correlator, cfg *config.Config) {
	if cfg == nil || !cfg.IncidentsAutoCloseEnabled() {
		return
	}
	rawThresholds := cfg.IncidentsAutoCloseThresholds()
	if len(rawThresholds) == 0 {
		return
	}
	thresholds := make(map[incident.Kind]time.Duration, len(rawThresholds))
	for k, v := range rawThresholds {
		thresholds[incident.Kind(k)] = v
	}
	dryRun := cfg.Incidents.AutoClose.DryRun
	closed, dryRunCount, scanned := c.CloseStale(time.Now(), thresholds, dryRun)
	if closed > 0 || dryRunCount > 0 {
		csmlog.Info("incident auto-close",
			"closed", closed,
			"dry_run_decisions", dryRunCount,
			"scanned", scanned,
			"dry_run", dryRun,
		)
	}
}

// startIncidentRetentionLoop runs a daily compaction sweep against the
// store. Started from IncidentCorrelator() once after the singleton is
// constructed. Logs errors but never panics. Returns the cancel func.
// The first sweep fires after one hour so the daemon has time to settle
// before touching the store under retention rules.
func startIncidentRetentionLoop(c *incident.Correlator) func() {
	stop := make(chan struct{})
	go func() {
		t := time.NewTicker(24 * time.Hour)
		defer t.Stop()
		first := time.NewTimer(time.Hour)
		defer first.Stop()
		for {
			select {
			case <-stop:
				return
			case <-first.C:
				runIncidentCompaction(c)
			case <-t.C:
				runIncidentCompaction(c)
			}
		}
	}()
	return func() { close(stop) }
}

// runIncidentCompaction prunes resolved/dismissed incidents older than
// the retention window and bumps the compacted_total counter so the
// metric reflects actual store work. Errors are logged, never fatal.
func runIncidentCompaction(c *incident.Correlator) {
	db := store.Global()
	if db == nil {
		return
	}
	now := time.Now()
	pruned, err := db.CompactIncidents(now, incidentRetentionPeriod)
	if err != nil {
		csmlog.Warn("incident retention compaction failed", "err", err)
		return
	}
	_ = c.PruneClosedOlderThan(now, incidentRetentionPeriod)
	_ = c.PruneStalePending(now)
	_ = c.PruneStaleSpray(now)
	if pruned > 0 {
		c.IncrementCompactedTotal(pruned)
		csmlog.Info("incident retention compaction", "pruned", pruned)
	}
}

// resetIncidentForTest is a test seam. Stops any retention worker, zeros
// the singleton, and pins the registry to a private one so subsequent
// IncidentCorrelator() calls do not collide on metrics.Default.
func resetIncidentForTest() {
	resetIncidentForTestWithThreshold(1)
}

// resetIncidentForTestWithThreshold is the same seam but lets a test pin
// the open threshold to a specific value. Used by the wiring test that
// proves the production default (2) is honored end-to-end through the
// IncidentCorrelator() singleton constructor.
func resetIncidentForTestWithThreshold(threshold int) {
	if incidentRetentionCancel != nil {
		incidentRetentionCancel()
		incidentRetentionCancel = nil
	}
	if incidentAutoCloseCancel != nil {
		incidentAutoCloseCancel()
		incidentAutoCloseCancel = nil
	}
	incidentCorrelator = nil
	incidentOnce = sync.Once{}
	incidentRegistry = metrics.NewRegistry
	globalCfgForIncidents = func() *config.Config { return nil }
	incidentSprayBlocker = nil
	// Most tests assert that one finding lands in one incident; the
	// production threshold of 2 would defer creation to the second
	// correlated event and break those wiring assertions. Pin to the
	// caller-supplied value; production callers never invoke this seam.
	incidentOpenThreshold = threshold
}
