package daemon

import (
	"sync"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/incident"
	csmlog "github.com/pidginhost/csm/internal/log"
	"github.com/pidginhost/csm/internal/metrics"
	"github.com/pidginhost/csm/internal/store"
)

var (
	incidentOnce            sync.Once
	incidentCorrelator      *incident.Correlator
	incidentRegistry        = metrics.Default
	incidentObsCancel       func()
	incidentRetentionCancel func()
)

// incidentRetentionPeriod is how long resolved/dismissed incidents are
// kept before compaction prunes them. Named constant per project
// convention; config exposure deferred until operators ask.
const incidentRetentionPeriod = 30 * 24 * time.Hour

// IncidentCorrelator returns the daemon-wide incident correlator.
// On first call: builds the correlator, restores prior state from
// the bbolt store (when available), registers metrics, and wires
// the alert-package observer that feeds it. Safe for concurrent
// callers.
func IncidentCorrelator() *incident.Correlator {
	incidentOnce.Do(func() {
		db := store.Global()
		var persist func(incident.Incident)
		if db != nil {
			persist = func(inc incident.Incident) {
				_ = db.SaveIncident(inc)
			}
		}
		incidentCorrelator = incident.NewCorrelator(incident.CorrelatorConfig{Persist: persist})
		if db != nil {
			if list, err := db.ListIncidents(); err == nil {
				incidentCorrelator.Restore(list)
			}
		}
		incident.RegisterMetrics(incidentRegistry(), incidentCorrelator)
		incidentObsCancel = wireIncidentObserver(incidentCorrelator)
		incidentRetentionCancel = startIncidentRetentionLoop(incidentCorrelator)
	})
	return incidentCorrelator
}

// wireIncidentObserver registers the alert-package observer that feeds
// the correlator. Exposed as a separate helper so tests can call it
// after a reset without going through sync.Once.
func wireIncidentObserver(c *incident.Correlator) func() {
	return alert.RegisterFindingObserver(func(f alert.Finding) {
		_, _, _ = c.OnFinding(f)
	})
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
	pruned, err := db.CompactIncidents(time.Now(), incidentRetentionPeriod)
	if err != nil {
		csmlog.Warn("incident retention compaction failed", "err", err)
		return
	}
	if pruned > 0 {
		c.IncrementCompactedTotal(pruned)
		csmlog.Info("incident retention compaction", "pruned", pruned)
	}
}

// resetIncidentForTest is a test seam. Stops any prior observer, zeros
// the singleton, and pins the registry to a private one so subsequent
// IncidentCorrelator() calls do not collide on metrics.Default.
func resetIncidentForTest() {
	if incidentObsCancel != nil {
		incidentObsCancel()
		incidentObsCancel = nil
	}
	if incidentRetentionCancel != nil {
		incidentRetentionCancel()
		incidentRetentionCancel = nil
	}
	incidentCorrelator = nil
	incidentOnce = sync.Once{}
	incidentRegistry = metrics.NewRegistry
}
