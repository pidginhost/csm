package daemon

import (
	"testing"

	"github.com/pidginhost/csm/internal/firewall"
)

// The challenge-timeout escalator must not claim a hard block landed when the
// engine actually no-opped (the IP was already blocked), dry-ran, or the
// verdict downgraded the call. A false "hard-blocked" line misleads incident
// review.
func TestChallengeEscalateLogLine(t *testing.T) {
	const ip = "192.0.2.50"

	tests := []struct {
		name    string
		outcome firewall.BlockOutcome
		want    string
	}{
		{
			name:    "live",
			outcome: firewall.BlockOutcomeLive,
			want:    "CHALLENGE-ESCALATE: 192.0.2.50 timed out, hard-blocked",
		},
		{
			name:    "dry-run",
			outcome: firewall.BlockOutcomeDryRun,
			want:    "CHALLENGE-ESCALATE [dry-run]: 192.0.2.50 timed out, would be hard-blocked",
		},
		{
			name:    "noop",
			outcome: firewall.BlockOutcomeNoop,
			want:    "challenge-escalate: 192.0.2.50 timed out, no new block (outcome: noop)",
		},
		{
			name:    "allowed",
			outcome: firewall.BlockOutcomeAllowed,
			want:    "challenge-escalate: 192.0.2.50 timed out, no new block (outcome: allowed)",
		},
		{
			name:    "allowlisted",
			outcome: firewall.BlockOutcomeAllowlisted,
			want:    "challenge-escalate: 192.0.2.50 timed out, no new block (outcome: allowlisted)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := challengeEscalateLogLine(ip, tt.outcome); got != tt.want {
				t.Fatalf("line = %q, want %q", got, tt.want)
			}
		})
	}
}

// Challenge-timeout escalations must be counted by firewall outcome so an
// operator can see how many challenges became real hard blocks (live) versus
// no-ops (the IP was already blocked).
func TestObserveChallengeEscalatedCountsByOutcome(t *testing.T) {
	observeChallengeEscalated(firewall.BlockOutcomeLive) // registers + increments
	liveBefore := challengeEscalatedMetric.With(string(firewall.BlockOutcomeLive)).Value()
	noopBefore := challengeEscalatedMetric.With(string(firewall.BlockOutcomeNoop)).Value()

	observeChallengeEscalated(firewall.BlockOutcomeLive)
	observeChallengeEscalated(firewall.BlockOutcomeNoop)

	if got := challengeEscalatedMetric.With(string(firewall.BlockOutcomeLive)).Value(); got != liveBefore+1 {
		t.Errorf("live delta = %v, want 1", got-liveBefore)
	}
	if got := challengeEscalatedMetric.With(string(firewall.BlockOutcomeNoop)).Value(); got != noopBefore+1 {
		t.Errorf("noop delta = %v, want 1", got-noopBefore)
	}
}
