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

// blockOutcomeMetricValue reads the exported counter value for one
// outcome/source pair from the default registry's exposition text, so the
// test asserts exactly what a scraper sees. Returns 0 when the child has
// not been created yet.
func blockOutcomeMetricValue(t *testing.T, outcome, source string) float64 {
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
			return v
		}
	}
	return 0
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
}
