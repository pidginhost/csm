package incident

import (
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/metrics"
)

func TestRegisterMetricsExposesAllExpectedNames(t *testing.T) {
	c := NewCorrelator(CorrelatorConfig{})
	reg := metrics.NewRegistry()
	RegisterMetrics(reg, c)

	var sb strings.Builder
	if err := reg.WriteOpenMetrics(&sb); err != nil {
		t.Fatalf("WriteOpenMetrics: %v", err)
	}
	out := sb.String()

	for _, name := range []string{
		"csm_incidents_open",
		"csm_incidents_created_total",
		"csm_incidents_severity_changed_total",
		"csm_incidents_status_changed_total",
		"csm_incidents_findings_merged_total",
		"csm_incidents_compacted_total",
		"csm_incidents_pending",
	} {
		if !strings.Contains(out, name) {
			t.Errorf("expected metric %q in output:\n%s", name, out)
		}
	}
}
