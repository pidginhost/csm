package checks

import (
	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

func init() {
	// CLI scans and standalone web UI dispatches also need this policy,
	// before any daemon is constructed. It depends only on check metadata
	// and the config passed to each call, not on a daemon's lifetime.
	alert.SetIPResponsePolicy(IPResponseAnswersFinding)
}

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
	switch f.Check {
	case "email_phishing_content", "email_malware":
		// Mail content may be evidence of a compromised local sender, and
		// any IP in its message may come from an untrusted mail header.
		return false
	case "mail_account_spray", "smtp_account_spray", "mail_subnet_spray", "smtp_subnet_spray",
		"http_distributed_flood", "http_asn_crawl":
		// These summarize many sources. SourceIP can be the latest sender
		// or a subnet; blocking one address does not answer the finding.
		return false
	}
	if blocked {
		return true
	}
	return challengeRoutesFinding(cfg, f)
}
