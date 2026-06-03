package daemon

import (
	"net"
	"sync"
	"time"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/incident"
	csmlog "github.com/pidginhost/csm/internal/log"
	"github.com/pidginhost/csm/internal/metrics"
	"github.com/pidginhost/csm/internal/store"
	"github.com/pidginhost/csm/internal/threatintel"
)

var (
	incidentOnce            sync.Once
	incidentCorrelator      *incident.Correlator
	incidentRegistry        = metrics.Default
	incidentRetentionCancel func()
	incidentAutoCloseCancel func()

	// incidentSprayBlocker is the firewall hand-off the daemon wires in
	// before IncidentCorrelator() is first invoked. The bool reports
	// whether nftables was actually mutated; dry-run, already-blocked,
	// and verdict-allow outcomes return false so incident timelines do
	// not record a live block that never landed.
	// nil means "no blocker wired" (early startup or unit tests); the
	// singleton then skips wiring OnSprayBlock and the spray detector
	// stays detection-only even with BlockAtSeverity set.
	incidentSprayBlocker func(ip, reason string, timeout time.Duration) (bool, error)
)

// SetIncidentSprayBlocker installs the firewall-side hand-off used by the
// incident auto-block paths. Call once after the firewall engine is built
// and before the first IncidentCorrelator() call.
// Passing nil clears the binding.
func SetIncidentSprayBlocker(fn func(ip, reason string, timeout time.Duration) (bool, error)) {
	incidentSprayBlocker = fn
}

// incidentAutoCloseInterval is how often the daemon scans Open / Contained
// incidents for staleness. One hour is fast enough that 24h-idle incidents
// close within ~25h worst-case, but slow enough that the per-kind walk
// stays cheap on hosts with thousands of incidents.
const incidentAutoCloseInterval = 1 * time.Hour

// incidentAutoCloseWarmup delays the first sweep just long enough for the
// startup finding burst to settle. Incidents are restored synchronously
// before the loop starts, so a long warm-up only parks a stale backlog as
// "open" after every restart (observed on a frequently-upgraded prod host:
// thousands of >24h incidents sitting open for the full warm-up). Short.
const incidentAutoCloseWarmup = 2 * time.Minute

// incidentAutoCloseDrainDelay is the cadence used when a sweep hit its
// per-sweep cap, so a large backlog drains over a few quick passes instead
// of waiting a full interval between each capped sweep.
const incidentAutoCloseDrainDelay = 30 * time.Second

// incidentAutoCloseMaxPerSweep bounds live closes per sweep so a big
// post-restart backlog does not hold the correlator lock or burst
// thousands of bbolt persists in one tick.
const incidentAutoCloseMaxPerSweep = 1000

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
				if err := db.SaveIncident(inc); err != nil {
					// The in-memory correlator has already advanced, so
					// failed writes mean the next restore may replay stale
					// incident state unless operators repair the store.
					csmlog.Warn("incident persist failed",
						"id", inc.ID, "kind", string(inc.Kind),
						"status", string(inc.Status), "err", err)
				}
			}
		}
		// Resolve spray-suppression knobs from the active config. nil
		// config (early test wiring) leaves the detector disabled.
		var spray incident.SpraySuppressionConfig
		var autoBlock incident.IncidentAutoBlockConfig
		var whitelisted func(string) bool
		var onSprayBlock func(ip, reason string) bool
		var onIncidentBlock func(ip, reason string) bool
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
				onSprayBlock = func(ip, reason string) bool {
					liveCfg := globalCfgForIncidents()
					if liveCfg == nil || !liveCfg.AutoResponse.Enabled || !liveCfg.AutoResponse.BlockIPs {
						return false
					}
					timeout, perr := time.ParseDuration(liveCfg.AutoResponse.BlockExpiry)
					if perr != nil || timeout <= 0 {
						timeout = 24 * time.Hour
					}
					live, err := blocker(ip, "CSM credential_spray: "+reason, timeout)
					if err != nil {
						csmlog.Warn("credential_spray block failed", "ip", ip, "err", err)
						return false
					}
					return live
				}
			}
			// Generic incident-driven auto-block. Reuses the same firewall
			// blocker as the spray path; the reason prefix differs so audit
			// log rows distinguish which detector triggered the block.
			kindsRaw := cfg.IncidentsAutoBlockKinds()
			kinds := make(map[incident.Kind]bool, len(kindsRaw))
			for k := range kindsRaw {
				kinds[incident.Kind(k)] = true
			}
			autoBlock = incident.IncidentAutoBlockConfig{
				Enabled:         cfg.Incidents.AutoBlock.Enabled,
				BlockAtSeverity: cfg.Incidents.AutoBlock.BlockAtSeverity,
				Kinds:           kinds,
			}
			if autoBlock.Enabled && autoBlock.BlockAtSeverity != "" && incidentSprayBlocker != nil {
				blocker := incidentSprayBlocker
				onIncidentBlock = func(ip, reason string) bool {
					liveCfg := globalCfgForIncidents()
					if liveCfg == nil || !liveCfg.AutoResponse.Enabled || !liveCfg.AutoResponse.BlockIPs {
						return false
					}
					timeout, perr := time.ParseDuration(liveCfg.AutoResponse.BlockExpiry)
					if perr != nil || timeout <= 0 {
						timeout = 24 * time.Hour
					}
					live, err := blocker(ip, "CSM incident: "+reason, timeout)
					if err != nil {
						csmlog.Warn("incident auto-block failed", "ip", ip, "err", err)
						return false
					}
					return live
				}
			}
			// Whitelist accessor: check the static reputation.whitelist
			// list, then the bbolt-backed live whitelist operators add at
			// runtime. db nil-check inside the closure so store resolution
			// stays current across daemon restarts.
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
				if d := store.Global(); d != nil && d.IsWhitelisted(ip) {
					return true
				}
				// Backstop: a verified-crawler IP from a published range
				// (Googlebot/Bingbot/Applebot) should never anchor a
				// correlated incident. CDN edge ranges are intentionally
				// excluded -- see threatintel.IPInAnyBot.
				return threatintel.DefaultRanges().IPInAnyBot(net.ParseIP(ip))
			}
		}
		incidentCorrelator = incident.NewCorrelator(incident.CorrelatorConfig{
			Persist:          persist,
			OpenThreshold:    incidentOpenThreshold,
			SpraySuppression: spray,
			AutoBlock:        autoBlock,
			IsWhitelisted:    whitelisted,
			CanSprayBlock: func() bool {
				cfg := globalCfgForIncidents()
				return cfg != nil && cfg.AutoResponse.Enabled && cfg.AutoResponse.BlockIPs
			},
			CanIncidentBlock: func() bool {
				cfg := globalCfgForIncidents()
				return cfg != nil && cfg.AutoResponse.Enabled && cfg.AutoResponse.BlockIPs
			},
			OnSprayBlock:    onSprayBlock,
			OnIncidentBlock: onIncidentBlock,
		})
		if db != nil {
			list, err := db.ListIncidents()
			if err != nil {
				csmlog.Warn("incident restore failed", "err", err)
			} else {
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
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		// Single resettable timer: first sweep after a short warm-up, then
		// the normal interval -- unless a sweep reports a remaining backlog,
		// in which case the next sweep fires on the fast drain cadence so a
		// post-restart backlog clears in minutes rather than over hours.
		timer := time.NewTimer(incidentAutoCloseWarmup)
		defer timer.Stop()
		for {
			select {
			case <-stop:
				return
			case <-timer.C:
				more := runIncidentAutoClose(c, cfg)
				next := incidentAutoCloseInterval
				if more {
					next = incidentAutoCloseDrainDelay
				}
				timer.Reset(next)
			}
		}
	}()
	// The cancel waits for the goroutine to actually exit, not just signal it,
	// so the daemon's shutdown sequence can guarantee no sweep is mid-bbolt-
	// write when it closes the store immediately after cancelling.
	return func() {
		close(stop)
		<-stopped
	}
}

// runIncidentAutoClose is one tick of the auto-close loop. Gated on
// the operator's config and on the per-kind threshold map. dry_run=true
// only increments counters; live mode flips Status -> resolved and
// records "auto:stale" attribution. Returns more=true when the per-sweep
// cap left stale incidents unclosed, so the caller schedules a prompt
// follow-up sweep instead of waiting the full interval.
func runIncidentAutoClose(c *incident.Correlator, cfg *config.Config) (more bool) {
	// The safety cap runs on every tick regardless of the operator's
	// auto-close toggle or per-kind thresholds. It is a hard backstop against
	// unbounded growth of Open/Contained incidents (in memory and bbolt) on a
	// host under sustained attack when auto-close is off or a kind is omitted.
	capMore := runIncidentSafetyCap(c)

	if cfg == nil || !cfg.IncidentsAutoCloseEnabled() {
		return capMore
	}
	rawThresholds := cfg.IncidentsAutoCloseThresholds()
	if len(rawThresholds) == 0 {
		return capMore
	}
	thresholds := make(map[incident.Kind]time.Duration, len(rawThresholds))
	for k, v := range rawThresholds {
		thresholds[incident.Kind(k)] = v
	}
	dryRun := cfg.Incidents.AutoClose.DryRun
	closed, dryRunCount, scanned, more := c.CloseStaleLimited(time.Now(), thresholds, dryRun, incidentAutoCloseMaxPerSweep)
	if closed > 0 || dryRunCount > 0 {
		csmlog.Info("incident auto-close",
			"closed", closed,
			"dry_run_decisions", dryRunCount,
			"scanned", scanned,
			"dry_run", dryRun,
			"backlog_remaining", more,
		)
	}
	return more || capMore
}

// incidentSafetyMaxAge is the hard age cap: any Open/Contained incident idle
// longer than this is force-closed regardless of auto-close config.
const incidentSafetyMaxAge = 30 * 24 * time.Hour

// incidentSafetyMaxActive bounds how many Open/Contained incidents are held in
// memory at once; the oldest over this are force-closed.
const incidentSafetyMaxActive = 50000

// runIncidentSafetyCap force-closes incidents past the age cap and trims the
// active set back under the size ceiling. Always runs, independent of the
// operator's auto-close settings. Returns more=true if either sweep left a
// backlog so the loop schedules a prompt follow-up.
func runIncidentSafetyCap(c *incident.Correlator) (more bool) {
	now := time.Now()
	byAge, ageMore := c.CloseStaleByAge(now, incidentSafetyMaxAge, incidentAutoCloseMaxPerSweep)
	byCap, capMore := c.EnforceActiveCap(now, incidentSafetyMaxActive, incidentAutoCloseMaxPerSweep)
	if byAge > 0 || byCap > 0 {
		csmlog.Info("incident safety cap",
			"closed_by_age", byAge,
			"closed_by_active_cap", byCap,
			"backlog_remaining", ageMore || capMore,
		)
	}
	return ageMore || capMore
}

// startIncidentRetentionLoop runs a daily compaction sweep against the
// store. Started from IncidentCorrelator() once after the singleton is
// constructed. Logs errors but never panics. Returns the cancel func.
// The first sweep fires after one hour so the daemon has time to settle
// before touching the store under retention rules.
func startIncidentRetentionLoop(c *incident.Correlator) func() {
	stop := make(chan struct{})
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
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
	// Wait for the goroutine to exit, so a compaction in flight finishes
	// before the daemon closes the store.
	return func() {
		close(stop)
		<-stopped
	}
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

// StopIncidentBackgroundLoops cancels the incident auto-close and retention
// goroutines. The daemon calls it during shutdown, before closing the store,
// so neither loop performs a bbolt write against an already-closed database.
// Safe to call when the singleton was never constructed (both cancels nil).
func StopIncidentBackgroundLoops() {
	if incidentRetentionCancel != nil {
		incidentRetentionCancel()
		incidentRetentionCancel = nil
	}
	if incidentAutoCloseCancel != nil {
		incidentAutoCloseCancel()
		incidentAutoCloseCancel = nil
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
