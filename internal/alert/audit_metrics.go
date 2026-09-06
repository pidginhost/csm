package alert

import "github.com/pidginhost/csm/internal/metrics"

var (
	auditSinkDegraded = metrics.NewGaugeVec("csm_audit_sink_degraded",
		"Configured audit destination unavailable or last delivery failed; 1 means degraded, 0 means healthy or disabled.", []string{"sink"})
	auditEventsDropped = metrics.NewCounterVec("csm_audit_events_dropped_total",
		"Audit events with unavailable destinations or failed writes.", []string{"sink"})
)

func init() {
	metrics.MustRegister("csm_audit_sink_degraded", auditSinkDegraded)
	metrics.MustRegister("csm_audit_events_dropped_total", auditEventsDropped)
}
