package checks

import (
	"sync/atomic"

	"github.com/pidginhost/csm/internal/metrics"
)

var directSMTPEgressFindingsTotal atomic.Uint64

// RegisterDirectSMTPEgressMetrics binds the per-finding counter to reg.
// Production callers should pass metrics.Default(); tests pass
// metrics.NewRegistry() to keep registration isolated.
func RegisterDirectSMTPEgressMetrics(reg *metrics.Registry) {
	reg.RegisterCounterFunc(
		"csm_direct_smtp_egress_findings_total",
		"Direct SMTP egress findings emitted by the connection consumer.",
		func() float64 { return float64(directSMTPEgressFindingsTotal.Load()) },
	)
}

// BumpDirectSMTPEgressFindings increments the per-finding counter.
// Called by the connection consumer when EvaluateDirectSMTPEgress
// returns a finding.
func BumpDirectSMTPEgressFindings() {
	directSMTPEgressFindingsTotal.Add(1)
}

// resetDirectSMTPEgressMetricsForTest is a test seam.
func resetDirectSMTPEgressMetricsForTest() {
	directSMTPEgressFindingsTotal.Store(0)
}
