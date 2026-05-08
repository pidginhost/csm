package daemon

import (
	"sync"

	"github.com/pidginhost/csm/internal/metrics"
)

// Decision label values match the BPF DECISION_* numeric codes:
// allow (0), dry_run (1), deny (2). Wire-stable strings; SIEM
// dashboards pin on them.
const (
	BPFDecisionAllow  = "allow"
	BPFDecisionDryRun = "dry_run"
	BPFDecisionDeny   = "deny"
)

var (
	bpfEnfMu                 sync.Mutex
	bpfEnfDecisionsVec       *metrics.CounterVec
	bpfEnfUIDRefreshTotal    *metrics.Counter
	bpfEnfUIDRefreshFailures *metrics.Counter
)

// RegisterBPFEnforcementMetrics registers the counters on reg. Production
// callers pass metrics.Default(); tests pass metrics.NewRegistry() to
// keep registration isolated.
func RegisterBPFEnforcementMetrics(reg *metrics.Registry) {
	bpfEnfMu.Lock()
	defer bpfEnfMu.Unlock()

	bpfEnfDecisionsVec = metrics.NewCounterVec(
		"csm_bpf_enforcement_decisions_total",
		"BPF cgroup-deny decisions by label (allow/dry_run/deny).",
		[]string{"decision"},
	)
	reg.MustRegister("csm_bpf_enforcement_decisions_total", bpfEnfDecisionsVec)

	bpfEnfUIDRefreshTotal = metrics.NewCounter(
		"csm_bpf_enforcement_uid_map_refresh_total",
		"BPF safe-UID map refresh successes.",
	)
	reg.MustRegister("csm_bpf_enforcement_uid_map_refresh_total", bpfEnfUIDRefreshTotal)

	bpfEnfUIDRefreshFailures = metrics.NewCounter(
		"csm_bpf_enforcement_uid_map_refresh_failures_total",
		"BPF safe-UID map refresh failures.",
	)
	reg.MustRegister("csm_bpf_enforcement_uid_map_refresh_failures_total", bpfEnfUIDRefreshFailures)
}

// BumpBPFEnforcementDecision advances the per-decision counter. Called
// from the connection consumer when a ConnectionEvent with a decision
// field arrives. Unknown labels are silently ignored (caller bug).
func BumpBPFEnforcementDecision(label string) {
	bpfEnfMu.Lock()
	cv := bpfEnfDecisionsVec
	bpfEnfMu.Unlock()
	if cv == nil {
		return
	}
	switch label {
	case BPFDecisionAllow, BPFDecisionDryRun, BPFDecisionDeny:
		cv.With(label).Inc()
	}
}

// BumpUIDRefresh advances the periodic-refresh success counter.
func BumpUIDRefresh() {
	bpfEnfMu.Lock()
	c := bpfEnfUIDRefreshTotal
	bpfEnfMu.Unlock()
	if c != nil {
		c.Inc()
	}
}

// BumpUIDRefreshFailure advances the periodic-refresh failure counter.
func BumpUIDRefreshFailure() {
	bpfEnfMu.Lock()
	c := bpfEnfUIDRefreshFailures
	bpfEnfMu.Unlock()
	if c != nil {
		c.Inc()
	}
}

// resetBPFEnforcementMetricsForTest is a test seam.
func resetBPFEnforcementMetricsForTest() {
	bpfEnfMu.Lock()
	defer bpfEnfMu.Unlock()
	bpfEnfDecisionsVec = nil
	bpfEnfUIDRefreshTotal = nil
	bpfEnfUIDRefreshFailures = nil
}
