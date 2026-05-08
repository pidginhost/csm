package daemon

import (
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/metrics"
)

func TestRegisterBPFEnforcementMetricsExposesNames(t *testing.T) {
	resetBPFEnforcementMetricsForTest()
	reg := metrics.NewRegistry()
	RegisterBPFEnforcementMetrics(reg)

	var sb strings.Builder
	if err := reg.WriteOpenMetrics(&sb); err != nil {
		t.Fatalf("WriteOpenMetrics: %v", err)
	}
	out := sb.String()
	for _, want := range []string{
		"csm_bpf_enforcement_decisions_total",
		"csm_bpf_enforcement_uid_map_refresh_total",
		"csm_bpf_enforcement_uid_map_refresh_failures_total",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
}

func TestBumpDecisionAdvancesPerLabel(t *testing.T) {
	resetBPFEnforcementMetricsForTest()
	reg := metrics.NewRegistry()
	RegisterBPFEnforcementMetrics(reg)
	BumpBPFEnforcementDecision(BPFDecisionAllow)
	BumpBPFEnforcementDecision(BPFDecisionDryRun)
	BumpBPFEnforcementDecision(BPFDecisionDeny)
	BumpBPFEnforcementDecision(BPFDecisionDeny)

	var sb strings.Builder
	if err := reg.WriteOpenMetrics(&sb); err != nil {
		t.Fatalf("WriteOpenMetrics: %v", err)
	}
	out := sb.String()
	for _, want := range []string{
		`csm_bpf_enforcement_decisions_total{decision="allow"} 1`,
		`csm_bpf_enforcement_decisions_total{decision="dry_run"} 1`,
		`csm_bpf_enforcement_decisions_total{decision="deny"} 2`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
}

func TestBumpUIDRefreshAdvancesCounter(t *testing.T) {
	resetBPFEnforcementMetricsForTest()
	reg := metrics.NewRegistry()
	RegisterBPFEnforcementMetrics(reg)
	BumpUIDRefresh()
	BumpUIDRefresh()
	BumpUIDRefreshFailure()

	var sb strings.Builder
	if err := reg.WriteOpenMetrics(&sb); err != nil {
		t.Fatalf("WriteOpenMetrics: %v", err)
	}
	out := sb.String()
	if !strings.Contains(out, "csm_bpf_enforcement_uid_map_refresh_total 2") {
		t.Errorf("refresh total: missing in:\n%s", out)
	}
	if !strings.Contains(out, "csm_bpf_enforcement_uid_map_refresh_failures_total 1") {
		t.Errorf("refresh failures: missing in:\n%s", out)
	}
}
