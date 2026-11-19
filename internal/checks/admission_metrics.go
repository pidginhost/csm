package checks

import (
	"sync"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/firewall"
	"github.com/pidginhost/csm/internal/metrics"
)

// ObserveAdmissionBlock records a live admission decision in the same
// counters as the legacy path. Queue deferrals and forecasts are not
// attempts; callers report only an engine outcome or a terminal refusal.
func ObserveAdmissionBlock(entry admission.Entry, outcome firewall.BlockOutcome, err error) {
	source := blockSourceUnknown
	switch entry {
	case admission.EntryScan:
		source = BlockSourceScan
	case admission.EntryChallengeTimeout:
		source = BlockSourceChallenge
	case admission.EntryIncident, admission.EntryIncidentSpray:
		source = BlockSourceIncident
	case admission.EntryCentral:
		source = BlockSourceCentral
	}
	observeBlockOutcome(outcome, err, source)
	if err != nil {
		return
	}
	if outcome == firewall.BlockOutcomeLive {
		observeAutoResponse("block", 1)
	}
	if entry == admission.EntryChallengeTimeout {
		ObserveChallengeEscalated(outcome)
	}
}

var (
	challengeEscalatedMetric     *metrics.CounterVec
	challengeEscalatedMetricOnce sync.Once
)

// challengeEscalatedCounter returns the lazily registered metric. Count paths
// use the same Once gate as increments so first status reads cannot race the
// first escalation.
func challengeEscalatedCounter() *metrics.CounterVec {
	challengeEscalatedMetricOnce.Do(func() {
		challengeEscalatedMetric = metrics.NewCounterVec(
			"csm_challenge_escalated_total",
			"Challenge-timeout escalations, by firewall outcome (live, noop, dry_run, allowed, allowlisted).",
			[]string{"outcome"},
		)
		metrics.MustRegister("csm_challenge_escalated_total", challengeEscalatedMetric)
	})
	return challengeEscalatedMetric
}

// ObserveChallengeEscalated counts one challenge-timeout escalation, labelled by
// the firewall outcome (live=a new hard block landed, noop=the IP was already
// blocked, plus dry_run/allowed/allowlisted). It lets operators see how many
// challenges became real blocks versus no-ops. Registered lazily on first use.
func ObserveChallengeEscalated(outcome firewall.BlockOutcome) {
	challengeEscalatedCounter().With(string(outcome)).Inc()
}

// ChallengeEscalatedCount returns the number of timeout escalations with
// outcome since process start. The challenge panel reads the live outcome.
func ChallengeEscalatedCount(outcome firewall.BlockOutcome) int {
	return int(challengeEscalatedCounter().With(string(outcome)).Value())
}
