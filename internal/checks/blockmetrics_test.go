package checks

import (
	"bytes"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/firewall"
	"github.com/pidginhost/csm/internal/metrics"
)

// blockOutcomeMetricSample reads one outcome/source pair from the default
// registry's exposition text, so the test asserts exactly what a scraper sees.
func blockOutcomeMetricSample(t *testing.T, outcome, source string) (float64, bool) {
	t.Helper()
	var buf bytes.Buffer
	if err := metrics.WriteOpenMetrics(&buf); err != nil {
		t.Fatal(err)
	}
	needle := fmt.Sprintf(`csm_firewall_block_outcome_total{outcome=%q,source=%q} `, outcome, source)
	for _, line := range strings.Split(buf.String(), "\n") {
		if strings.HasPrefix(line, needle) {
			v, err := strconv.ParseFloat(strings.TrimPrefix(line, needle), 64)
			if err != nil {
				t.Fatalf("parse metric line %q: %v", line, err)
			}
			return v, true
		}
	}
	return 0, false
}

func blockOutcomeMetricValue(t *testing.T, outcome, source string) float64 {
	t.Helper()
	v, _ := blockOutcomeMetricSample(t, outcome, source)
	return v
}

// Every chokepoint block attempt increments
// csm_firewall_block_outcome_total with its outcome and source, so a
// dashboard can prove auto-response is alive (or show it silently dead).
func TestApplyBlockIncrementsOutcomeMetric(t *testing.T) {
	cfg := pendingTestConfig(t)
	blocker := &outcomeStubBlocker{outcome: firewall.BlockOutcomeLive}
	applyBlockTestSetup(t, blocker)

	before := blockOutcomeMetricValue(t, "live", BlockSourceChallenge)
	if _, err := ApplyBlock(cfg, ApplyBlockRequest{
		IP: "203.0.113.57", EngineReason: "r", Reason: "r",
		TTL: time.Hour, Source: BlockSourceChallenge,
	}); err != nil {
		t.Fatalf("ApplyBlock: %v", err)
	}
	if got := blockOutcomeMetricValue(t, "live", BlockSourceChallenge); got != before+1 {
		t.Fatalf("live/challenge = %v, want %v", got, before+1)
	}
}

// Engine failures are visible in the same metric: generic errors count as
// outcome=error, protected-IP refusals as outcome=protected so expected
// no-ops do not masquerade as failures.
func TestApplyBlockCountsErrorAndProtectedOutcomes(t *testing.T) {
	cfg := pendingTestConfig(t)

	errBlocker := &outcomeStubBlocker{outcome: firewall.BlockOutcomeNoop, err: errors.New("netlink down")}
	applyBlockTestSetup(t, errBlocker)
	beforeErr := blockOutcomeMetricValue(t, "error", BlockSourceCentral)
	_, _ = ApplyBlock(cfg, ApplyBlockRequest{
		IP: "203.0.113.58", EngineReason: "r", Reason: "r",
		TTL: time.Hour, Source: BlockSourceCentral,
	})
	if got := blockOutcomeMetricValue(t, "error", BlockSourceCentral); got != beforeErr+1 {
		t.Fatalf("error/central = %v, want %v", got, beforeErr+1)
	}

	protBlocker := &outcomeStubBlocker{outcome: firewall.BlockOutcomeNoop, err: firewall.ErrIPProtected}
	SetIPBlocker(protBlocker)
	beforeProt := blockOutcomeMetricValue(t, "protected", BlockSourceIncident)
	_, _ = ApplyBlock(cfg, ApplyBlockRequest{
		IP: "203.0.113.59", EngineReason: "r", Reason: "r",
		TTL: time.Hour, Source: BlockSourceIncident,
	})
	if got := blockOutcomeMetricValue(t, "protected", BlockSourceIncident); got != beforeProt+1 {
		t.Fatalf("protected/incident = %v, want %v", got, beforeProt+1)
	}
}

// Operator paths report through the same metric via ObserveOperatorBlock.
func TestObserveOperatorBlockCountsCLI(t *testing.T) {
	before := blockOutcomeMetricValue(t, "live", BlockSourceCLI)
	ObserveOperatorBlock(nil, BlockSourceCLI)
	if got := blockOutcomeMetricValue(t, "live", BlockSourceCLI); got != before+1 {
		t.Fatalf("live/cli = %v, want %v", got, before+1)
	}

	beforeErr := blockOutcomeMetricValue(t, "error", BlockSourceWebUI)
	ObserveOperatorBlock(errors.New("engine down"), BlockSourceWebUI)
	if got := blockOutcomeMetricValue(t, "error", BlockSourceWebUI); got != beforeErr+1 {
		t.Fatalf("error/web_ui = %v, want %v", got, beforeErr+1)
	}

	beforeProtected := blockOutcomeMetricValue(t, "protected", BlockSourceWebUI)
	beforeErr = blockOutcomeMetricValue(t, "error", BlockSourceWebUI)
	ObserveOperatorBlock(fmt.Errorf("operator guard: %w", firewall.ErrIPProtected), BlockSourceWebUI)
	if got := blockOutcomeMetricValue(t, "protected", BlockSourceWebUI); got != beforeProtected+1 {
		t.Fatalf("protected/web_ui = %v, want %v", got, beforeProtected+1)
	}
	if got := blockOutcomeMetricValue(t, "error", BlockSourceWebUI); got != beforeErr {
		t.Fatalf("error/web_ui = %v after protected refusal, want %v", got, beforeErr)
	}
}

func TestBlockOutcomeMetricPreinitializesClosedLabelSet(t *testing.T) {
	outcomes := []string{"live", "dry_run", "allowed", "allowlisted", "noop", "protected", "error"}
	sources := []string{
		BlockSourceScan,
		BlockSourceChallenge,
		BlockSourceIncident,
		BlockSourceCentral,
		BlockSourceCLI,
		BlockSourceWebUI,
		"unknown",
	}

	for _, outcome := range outcomes {
		for _, source := range sources {
			if _, ok := blockOutcomeMetricSample(t, outcome, source); !ok {
				t.Errorf("missing zero-value metric for outcome=%q source=%q", outcome, source)
			}
		}
	}
	if got, want := blockOutcomeCounter().ChildCount(), len(outcomes)*len(sources); got != want {
		t.Fatalf("metric children = %d, want the %d closed label combinations", got, want)
	}
}

func TestObserveBlockOutcomeCollapsesUnexpectedLabels(t *testing.T) {
	counter := blockOutcomeCounter()
	beforeChildren := counter.ChildCount()
	before := blockOutcomeMetricValue(t, "error", "unknown")

	for i := range 128 {
		observeBlockOutcome(
			firewall.BlockOutcome(fmt.Sprintf("203.0.113.%d", i)),
			nil,
			fmt.Sprintf("untrusted reason %d", i),
		)
	}

	if got := blockOutcomeMetricValue(t, "error", "unknown"); got != before+128 {
		t.Fatalf("error/unknown = %v, want %v", got, before+128)
	}
	if got := counter.ChildCount(); got != beforeChildren {
		t.Fatalf("metric children grew from %d to %d for unexpected labels", beforeChildren, got)
	}
}
