package webui

import (
	"bytes"
	"strconv"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/metrics"
)

func webBlockOutcomeValue(t *testing.T, outcome, source string) float64 {
	t.Helper()
	var buf bytes.Buffer
	if err := metrics.WriteOpenMetrics(&buf); err != nil {
		t.Fatal(err)
	}
	needle := `csm_firewall_block_outcome_total{outcome="` + outcome + `",source="` + source + `"} `
	for _, line := range strings.Split(buf.String(), "\n") {
		if strings.HasPrefix(line, needle) {
			v, err := strconv.ParseFloat(strings.TrimPrefix(line, needle), 64)
			if err != nil {
				t.Fatalf("parse metric line %q: %v", line, err)
			}
			return v
		}
	}
	return 0
}

// Web UI operator blocks report into the shared firewall outcome metric so
// dashboards see every block source.
func TestBlockIPForOperatorCountsMetric(t *testing.T) {
	before := webBlockOutcomeValue(t, "live", checks.BlockSourceWebUI)
	if err := blockIPForOperator(newFullBlocker(), "203.0.113.75", "manual block", 0); err != nil {
		t.Fatalf("blockIPForOperator: %v", err)
	}
	if got := webBlockOutcomeValue(t, "live", checks.BlockSourceWebUI); got != before+1 {
		t.Fatalf("live/web_ui = %v, want %v", got, before+1)
	}
}
