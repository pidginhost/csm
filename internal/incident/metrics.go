package incident

import "github.com/pidginhost/csm/internal/metrics"

// RegisterMetrics binds the correlator's counters to reg. Production
// callers should pass metrics.Default(); tests pass metrics.NewRegistry()
// to keep registration isolated.
func RegisterMetrics(reg *metrics.Registry, c *Correlator) {
	reg.RegisterGaugeFunc(
		"csm_incidents_open",
		"Open and Contained incidents currently in correlator state.",
		func() float64 { return float64(c.OpenCount()) },
	)
	reg.RegisterCounterFunc(
		"csm_incidents_created_total",
		"Total incidents created by the correlator.",
		func() float64 { return float64(c.counters.createdTotal.Load()) },
	)
	reg.RegisterCounterFunc(
		"csm_incidents_severity_changed_total",
		"Incident severity escalations (severity does not downgrade, so this is monotonic).",
		func() float64 { return float64(c.counters.severityChangedTotal.Load()) },
	)
	reg.RegisterCounterFunc(
		"csm_incidents_status_changed_total",
		"Incident status transitions (open/contained/resolved/dismissed).",
		func() float64 { return float64(c.counters.statusChangedTotal.Load()) },
	)
	reg.RegisterCounterFunc(
		"csm_incidents_findings_merged_total",
		"Findings merged into an existing incident (not counted on incident create).",
		func() float64 { return float64(c.counters.findingsMergedTotal.Load()) },
	)
	reg.RegisterCounterFunc(
		"csm_incidents_compacted_total",
		"Incidents pruned by retention compaction (resolved/dismissed beyond TTL).",
		func() float64 { return float64(c.counters.compactedTotal.Load()) },
	)
	reg.RegisterGaugeFunc(
		"csm_incidents_pending",
		"Findings held in the threshold gate, awaiting a second correlated finding before opening an incident.",
		func() float64 { return float64(c.PendingCount()) },
	)
	reg.RegisterCounterFunc(
		"csm_incidents_auto_closed_total",
		"Open or contained incidents auto-resolved after exceeding their per-kind idle threshold.",
		func() float64 { return float64(c.counters.autoClosedTotal.Load()) },
	)
	reg.RegisterCounterFunc(
		"csm_incidents_auto_close_dry_run_total",
		"Auto-close decisions counted while dry_run was active (state unchanged).",
		func() float64 { return float64(c.counters.autoCloseDryRunTotal.Load()) },
	)
}
