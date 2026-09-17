package checks

import (
	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

// IPResponseAnswersFinding is the alert.IPResponsePolicy for
// suppress_blocked_alerts. A block or challenge on the source address answers
// only attacker-side findings: attacker activity or attempted access that is
// not evidence of compromise. Once the source is stopped the operator has
// nothing left to do. Compromise evidence, successful logins and audit events
// stay visible even when their source address is already blocked.
//
// A challenge answers only the findings challenge routing would send to the
// gate. The address being on the challenge list is itself proof the gate is
// in use, so the policy does not consult challenge.enabled.
func IPResponseAnswersFinding(cfg *config.Config, f alert.Finding, blocked bool) bool {
	if correlationReasonOf(f.Check) != reasonAttackerSide {
		return false
	}
	if blocked {
		return true
	}
	return challengeRoutesFinding(cfg, f)
}
