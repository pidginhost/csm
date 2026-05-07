package daemon

import (
	"sync"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/incident"
	"github.com/pidginhost/csm/internal/metrics"
	"github.com/pidginhost/csm/internal/store"
)

var (
	incidentOnce       sync.Once
	incidentCorrelator *incident.Correlator
	incidentRegistry   = metrics.Default
	incidentObsCancel  func()
)

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

// resetIncidentForTest is a test seam. Stops any prior observer, zeros
// the singleton, and pins the registry to a private one so subsequent
// IncidentCorrelator() calls do not collide on metrics.Default.
func resetIncidentForTest() {
	if incidentObsCancel != nil {
		incidentObsCancel()
		incidentObsCancel = nil
	}
	incidentCorrelator = nil
	incidentOnce = sync.Once{}
	incidentRegistry = metrics.NewRegistry
}
