package daemon

import (
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/firewall"
)

// The challenge-timeout escalator must not claim a hard block landed when the
// engine actually no-opped (the IP was already blocked) or the verdict
// downgraded the call. A false "hard-blocked" line misleads incident review.
func TestChallengeEscalateLogLine(t *testing.T) {
	const ip = "192.0.2.50"

	live := challengeEscalateLogLine(ip, firewall.BlockOutcomeLive)
	if !strings.Contains(live, "hard-blocked") || strings.Contains(live, "no new block") {
		t.Errorf("live outcome line = %q, want a hard-blocked claim", live)
	}

	for _, oc := range []firewall.BlockOutcome{firewall.BlockOutcomeNoop, firewall.BlockOutcomeAllowed} {
		got := challengeEscalateLogLine(ip, oc)
		if strings.Contains(got, "hard-blocked") {
			t.Errorf("outcome %q line = %q, must not claim a block landed", oc, got)
		}
		if !strings.Contains(got, "no new block") {
			t.Errorf("outcome %q line = %q, want a no-new-block notice", oc, got)
		}
	}
}
