package checks

import (
	"bytes"
	"context"
	"strconv"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/metrics"
	"github.com/pidginhost/csm/internal/state"
)

// TestRunParallelObservesCheckDuration confirms the histogram wiring
// stays connected. A silent regression (someone deletes the
// observeCheckDuration call from runParallel) would pass every other
// test in this package; this one catches it by running the real
// runParallel against a stub check and asserting the scrape grew.
func TestRunParallelObservesCheckDuration(t *testing.T) {
	before := scrapeSum(t, "csm_check_duration_seconds_count")

	stub := []namedCheck{
		{"metrics_smoke_noop", func(_ context.Context, _ *config.Config, _ *state.Store) []alert.Finding {
			return nil
		}},
	}
	runParallel(&config.Config{}, nil, stub, "critical")

	after := scrapeSum(t, "csm_check_duration_seconds_count")
	if after-before < 1 {
		t.Fatalf("csm_check_duration_seconds_count did not increase: before=%g after=%g", before, after)
	}

	// Also verify the label we supplied made it through the
	// histogram vector.
	body := scrape(t)
	if !strings.Contains(body, `name="metrics_smoke_noop"`) || !strings.Contains(body, `tier="critical"`) {
		t.Errorf("scrape missing {name,tier} for smoke-noop check:\n%s", body)
	}
}

// TestObserveAutoResponseWiring verifies the auto-response counter
// increments by action class and the labels reach the scrape.
//
// We call the observeAutoResponse helper directly rather than running
// a full tier against fake Auto* functions: AutoKillProcesses,
// AutoQuarantineFiles, and AutoBlockIPs all touch live system state
// that a unit test cannot stub cleanly. Coverage of the call sites
// inside runParallel is verified by reading code (three observation
// points, one per Auto* return value). The helper itself is the
// metric-wiring single point of failure, so that is what we test.
func TestObserveAutoResponseWiring(t *testing.T) {
	before := scrapeCounterByAction(t)

	observeAutoResponse("kill", 3)
	observeAutoResponse("quarantine", 1)
	observeAutoResponse("block", 4)
	observeAutoResponse("kill", 2)

	after := scrapeCounterByAction(t)
	if got := after["kill"] - before["kill"]; got != 5 {
		t.Errorf("kill delta: got %g want 5", got)
	}
	if got := after["quarantine"] - before["quarantine"]; got != 1 {
		t.Errorf("quarantine delta: got %g want 1", got)
	}
	if got := after["block"] - before["block"]; got != 4 {
		t.Errorf("block delta: got %g want 4", got)
	}
}

// TestObserveAutoResponseZeroIsNoop: zero-count batches should not
// create a spurious counter entry with value 0.
func TestObserveAutoResponseZeroIsNoop(t *testing.T) {
	before := scrapeCounterByAction(t)
	observeAutoResponse("kill", 0)
	observeAutoResponse("block", -1)
	after := scrapeCounterByAction(t)
	for action, v := range after {
		if v != before[action] {
			t.Errorf("action %q: got delta %g want 0 (n=0 or negative should be skipped)", action, v-before[action])
		}
	}
}

// -----------------------------------------------------------------------
// helpers
// -----------------------------------------------------------------------

func scrape(t *testing.T) string {
	t.Helper()
	var buf bytes.Buffer
	if err := metrics.WriteOpenMetrics(&buf); err != nil {
		t.Fatalf("WriteOpenMetrics: %v", err)
	}
	return buf.String()
}

// scrapeSum finds every sample for the given metric name and returns
// their sum. Works for both labelled and unlabelled counters/counts.
func scrapeSum(t *testing.T, name string) float64 {
	t.Helper()
	body := scrape(t)
	sum := 0.0
	for _, line := range strings.Split(body, "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Match either `name 42` or `name{...} 42`.
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, name) {
			continue
		}
		rest := trimmed[len(name):]
		if rest != "" && rest[0] != ' ' && rest[0] != '{' {
			continue
		}
		// Skip past labels if present.
		if rest != "" && rest[0] == '{' {
			end := strings.Index(rest, "}")
			if end < 0 {
				continue
			}
			rest = rest[end+1:]
		}
		value := strings.TrimSpace(rest)
		if value == "" {
			continue
		}
		f := 0.0
		for _, field := range strings.Fields(value) {
			parsed, err := parseScraperFloat(field)
			if err != nil {
				continue
			}
			f = parsed
			break
		}
		sum += f
	}
	return sum
}

func scrapeCounterByAction(t *testing.T) map[string]float64 {
	t.Helper()
	body := scrape(t)
	out := map[string]float64{"kill": 0, "quarantine": 0, "block": 0}
	for _, line := range strings.Split(body, "\n") {
		if !strings.HasPrefix(line, `csm_auto_response_actions_total{action=`) {
			continue
		}
		open := strings.Index(line, `"`)
		if open < 0 {
			continue
		}
		rest := line[open+1:]
		end := strings.Index(rest, `"`)
		if end < 0 {
			continue
		}
		action := rest[:end]
		after := strings.TrimSpace(strings.TrimPrefix(rest[end+1:], "}"))
		if after == "" {
			continue
		}
		v, err := parseScraperFloat(after)
		if err != nil {
			continue
		}
		out[action] = v
	}
	return out
}

func parseScraperFloat(s string) (float64, error) {
	return strconv.ParseFloat(strings.TrimSpace(s), 64)
}
