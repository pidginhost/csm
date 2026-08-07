package checks

import (
	"errors"
	"sync"

	"github.com/pidginhost/csm/internal/firewall"
	"github.com/pidginhost/csm/internal/metrics"
)

// Operator block sources, alongside the auto-response sources in
// applyblock.go. Operator paths bypass the chokepoint (they force-block and
// audit separately) but report into the same outcome metric.
const (
	BlockSourceCLI   = "cli"
	BlockSourceWebUI = "web_ui"
)

var (
	blockOutcomeMetric     *metrics.CounterVec
	blockOutcomeMetricOnce sync.Once
)

// blockOutcomeCounter lazily registers the outcome metric. The same Once
// gates increments and reads so a scrape cannot race the first block.
func blockOutcomeCounter() *metrics.CounterVec {
	blockOutcomeMetricOnce.Do(func() {
		blockOutcomeMetric = metrics.NewCounterVec(
			"csm_firewall_block_outcome_total",
			"Firewall IP block attempts by outcome (live, dry_run, allowed, allowlisted, noop, protected, error) and source (scan, challenge, incident, central_intel, cli, web_ui).",
			[]string{"outcome", "source"},
		)
		metrics.MustRegister("csm_firewall_block_outcome_total", blockOutcomeMetric)
	})
	return blockOutcomeMetric
}

// observeBlockOutcome counts one block attempt. Protected-IP refusals get
// their own label so expected no-ops do not read as failures on dashboards;
// every other error is outcome=error.
func observeBlockOutcome(outcome firewall.BlockOutcome, err error, source string) {
	label := string(outcome)
	if err != nil {
		label = "error"
		if errors.Is(err, firewall.ErrIPProtected) {
			label = "protected"
		}
	}
	blockOutcomeCounter().With(label, source).Inc()
}

// ObserveOperatorBlock reports an operator-initiated force block (CLI or
// web UI) into the outcome metric. Force blocks bypass the dry-run gate, so
// a nil error means the block landed live.
func ObserveOperatorBlock(err error, source string) {
	outcome := firewall.BlockOutcomeLive
	observeBlockOutcome(outcome, err, source)
}
