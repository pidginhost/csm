package daemon

import (
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/metrics"
)

func TestPHPRelayMetrics_RegisterAndScrape(t *testing.T) {
	m := newPHPRelayMetrics()
	m.Findings.With("header").Inc()
	m.ActiveMsgsCapped.Inc()

	var sb strings.Builder
	if err := metrics.WriteOpenMetrics(&sb); err != nil {
		t.Fatal(err)
	}
	out := sb.String()
	if !strings.Contains(out, "csm_php_relay_findings_total") {
		t.Errorf("findings_total not exposed:\n%s", out)
	}
	if !strings.Contains(out, "csm_php_relay_active_msgs_capped_total") {
		t.Errorf("active_msgs_capped_total not exposed:\n%s", out)
	}
}
