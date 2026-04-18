package state

import (
	"bytes"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/metrics"
)

func TestAppendHistoryIncrementsFindingsMetric(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("state.Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	// Read the current counter value before writing new findings.
	// The metric is registered via sync.Once and is process-wide, so
	// earlier tests in this binary may have already bumped it.
	before := scrapeFindingsBySeverity(t)

	s.AppendHistory([]alert.Finding{
		{Severity: alert.Critical, Check: "x", Message: "m", Timestamp: time.Now()},
		{Severity: alert.Critical, Check: "y", Message: "m", Timestamp: time.Now()},
		{Severity: alert.Warning, Check: "z", Message: "m", Timestamp: time.Now()},
	})

	after := scrapeFindingsBySeverity(t)

	if got := after["CRITICAL"] - before["CRITICAL"]; got != 2 {
		t.Errorf("CRITICAL delta: got %g want 2", got)
	}
	if got := after["WARNING"] - before["WARNING"]; got != 1 {
		t.Errorf("WARNING delta: got %g want 1", got)
	}
}

func TestAppendHistoryEmptyDoesNotBumpMetric(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("state.Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	before := scrapeFindingsBySeverity(t)
	s.AppendHistory(nil)
	s.AppendHistory([]alert.Finding{})
	after := scrapeFindingsBySeverity(t)

	for sev, v := range after {
		if v != before[sev] {
			t.Errorf("severity %q: got delta %g want 0", sev, v-before[sev])
		}
	}
}

// scrapeFindingsBySeverity parses the csm_findings_total{severity=...}
// lines out of a scrape and returns a severity->value map.
func scrapeFindingsBySeverity(t *testing.T) map[string]float64 {
	t.Helper()
	var buf bytes.Buffer
	if err := metrics.WriteOpenMetrics(&buf); err != nil {
		t.Fatalf("scrape: %v", err)
	}
	out := map[string]float64{
		"CRITICAL": 0,
		"HIGH":     0,
		"WARNING":  0,
	}
	for _, line := range strings.Split(buf.String(), "\n") {
		if !strings.HasPrefix(line, "csm_findings_total{severity=") {
			continue
		}
		// Expected shape: csm_findings_total{severity="CRITICAL"} 2
		open := strings.Index(line, `"`)
		if open < 0 {
			continue
		}
		rest := line[open+1:]
		close := strings.Index(rest, `"`)
		if close < 0 {
			continue
		}
		sev := rest[:close]
		valuePart := strings.TrimSpace(strings.TrimPrefix(rest[close+1:], "}"))
		if valuePart == "" {
			continue
		}
		v, err := strconv.ParseFloat(valuePart, 64)
		if err != nil {
			continue
		}
		out[sev] = v
	}
	return out
}
