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

	blockSourceUnknown    = "unknown"
	blockOutcomeError     = "error"
	blockOutcomeProtected = "protected"
)

var (
	blockOutcomeMetric     *metrics.CounterVec
	blockOutcomeMetricOnce sync.Once
	blockOutcomeLabels     = [...]string{
		string(firewall.BlockOutcomeLive),
		string(firewall.BlockOutcomeDryRun),
		string(firewall.BlockOutcomeAllowed),
		string(firewall.BlockOutcomeAllowlisted),
		string(firewall.BlockOutcomeNoop),
		blockOutcomeProtected,
		blockOutcomeError,
	}
	blockSourceLabels = [...]string{
		BlockSourceScan,
		BlockSourceChallenge,
		BlockSourceIncident,
		BlockSourceCentral,
		BlockSourceCLI,
		BlockSourceWebUI,
		blockSourceUnknown,
	}
)

func init() {
	// An aliveness alert needs zero-value series before the first attempt;
	// otherwise Prometheus treats a dead block path as missing data.
	blockOutcomeCounter()
}

// blockOutcomeCounter registers the outcome metric once and creates every
// closed label combination so zero-attempt paths remain visible to scrapes.
func blockOutcomeCounter() *metrics.CounterVec {
	blockOutcomeMetricOnce.Do(func() {
		blockOutcomeMetric = metrics.NewCounterVec(
			"csm_firewall_block_outcome_total",
			"Firewall IP block attempts by outcome (live, dry_run, allowed, allowlisted, noop, protected, error) and source (scan, challenge, incident, central_intel, cli, web_ui, unknown).",
			[]string{"outcome", "source"},
		)
		// CounterVec reserves one child for overflow, so allow the complete
		// closed set plus that defensive sentinel and no further growth.
		blockOutcomeMetric.SetMaxChildren(len(blockOutcomeLabels)*len(blockSourceLabels) + 1)
		for _, outcome := range blockOutcomeLabels {
			for _, source := range blockSourceLabels {
				blockOutcomeMetric.With(outcome, source)
			}
		}
		metrics.MustRegister("csm_firewall_block_outcome_total", blockOutcomeMetric)
	})
	return blockOutcomeMetric
}

// observeBlockOutcome counts one block attempt. Protected-IP refusals get
// their own label so expected no-ops do not read as failures on dashboards;
// every other error is outcome=error.
func observeBlockOutcome(outcome firewall.BlockOutcome, err error, source string) {
	blockOutcomeCounter().With(blockOutcomeLabel(outcome, err), blockSourceLabel(source)).Inc()
}

func blockOutcomeLabel(outcome firewall.BlockOutcome, err error) string {
	if errors.Is(err, firewall.ErrIPProtected) {
		return blockOutcomeProtected
	}
	if err != nil {
		return blockOutcomeError
	}
	switch outcome {
	case firewall.BlockOutcomeLive,
		firewall.BlockOutcomeDryRun,
		firewall.BlockOutcomeAllowed,
		firewall.BlockOutcomeAllowlisted,
		firewall.BlockOutcomeNoop:
		return string(outcome)
	default:
		// An implementation that returns an undocumented outcome violated the
		// engine contract; report it as an error without creating a new label.
		return blockOutcomeError
	}
}

func blockSourceLabel(source string) string {
	switch source {
	case BlockSourceScan,
		BlockSourceChallenge,
		BlockSourceIncident,
		BlockSourceCentral,
		BlockSourceCLI,
		BlockSourceWebUI:
		return source
	default:
		return blockSourceUnknown
	}
}

// ObserveOperatorBlock reports an operator-initiated force block (CLI or
// web UI) into the outcome metric. Force blocks bypass the dry-run gate, so
// a nil error means the block landed live.
func ObserveOperatorBlock(err error, source string) {
	outcome := firewall.BlockOutcomeLive
	observeBlockOutcome(outcome, err, source)
}
