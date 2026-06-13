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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := challengeEscalateLogLine(ip, tt.outcome); got != tt.want {
				t.Fatalf("line = %q, want %q", got, tt.want)
			}
		})
	}
}
