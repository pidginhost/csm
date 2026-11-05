package checks

import (
	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/firewall"
)

func init() {
	// CLI scans and standalone web UI dispatches also need these policies,
	// before any daemon is constructed. They depend only on check metadata
	// and the config passed to each call, not on a daemon's lifetime.
	alert.SetIPResponsePolicy(IPResponseAnswersFinding)
	alert.SetSummaryNoticePolicy(IsSummaryNotice)
}

// IPResponseAnswersFinding is the alert.IPResponsePolicy that decides which
// findings about a handled source go to the summary. A block or challenge on
// the source address answers only attacker-side findings: attacker activity
// or attempted access that is not evidence of compromise. Once the source is
// stopped the operator has nothing left to do. Compromise evidence,
// successful logins and audit events stay immediate even when their source
// address is already blocked.
//
// A challenge answers only the findings challenge routing would send to the
// gate. The address being on the challenge list is itself proof the gate is
// in use, so the policy does not consult challenge.enabled.
func IPResponseAnswersFinding(cfg *config.Config, f alert.Finding, blocked bool) bool {
	if correlationReasonOf(f.Check) != reasonAttackerSide {
		return false
	}
	switch f.Check {
	case "whm_unauth_scripts_realtime":
		// An exploit indicator: a later block cannot tell whether the
		// tokenless request already succeeded, so a person must check.
		return false
	case "email_phishing_content", "email_malware", "email_av_parse_worker_source":
		// Mail content may be evidence of a compromised local sender, and
		// an IP in the message may come from a mail header or an account
		// name. A parse source can also represent a whole IPv6 subnet.
		return false
	case "mail_account_spray", "smtp_account_spray", "mail_subnet_spray", "smtp_subnet_spray",
		"http_distributed_flood", "http_asn_crawl":
		// These summarize many sources. SourceIP can be the latest sender
		// or a subnet; blocking one address does not answer the finding.
		return false
	}
	if blocked {
		// The Cloudflare accept on TCP 80/443 precedes the blocked drop, so
		// a block of a covered address leaves its web traffic flowing.
		return !webTrafficFinding(f) || !cloudflareCoversSource(cfg, f)
	}
	return challengeRoutesFinding(cfg, f)
}

// webTrafficFinding reports whether f is about requests on the web ports: an
// HTTP-family check, or a reputation sighting below Critical, which is
// browser-facing traffic.
func webTrafficFinding(f alert.Finding) bool {
	// Raw WAF observations never authorize a response, so their response
	// policy has no evidence family. They still describe HTTP traffic.
	switch f.Check {
	case "modsec_block_realtime", "modsec_warning_realtime", "modsec_low_confidence_burst":
		return true
	}
	return ResponsePolicyFor(f.Check).Evidence == admission.FamilyHTTP ||
		(f.Check == "ip_reputation" && f.Severity != alert.Critical)
}

// cloudflareCoversSource reads the Cloudflare ranges the firewall accepts on
// its web ports, the list a block notice's coverage warning comes from.
func cloudflareCoversSource(cfg *config.Config, f alert.Finding) bool {
	ip := alert.ClassSourceIP(f)
	if cfg == nil || ip == nil {
		return false
	}
	v4, v6 := firewall.LoadCFState(cfg.StatePath)
	return firewall.CloudflareRangesCover(v4, v6, ip.String())
}
