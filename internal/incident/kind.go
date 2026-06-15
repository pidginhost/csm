package incident

import (
	"strings"

	"github.com/pidginhost/csm/internal/alert"
)

// ClassifyKind returns the incident Kind for a Finding using simple rule
// precedence: mailbox/SMTP signals first (mailbox_takeover), then
// host-integrity checks, then ephemeral-path process exec, then the
// account-scoped web-compromise default.
func ClassifyKind(f alert.Finding) Kind {
	check := strings.ToLower(f.Check)

	// Mailbox takeover -- any check with a Mailbox attribute or a
	// mailbox-auth check name. Mailbox attribution is the
	// strongest single signal so it wins over generic check-name
	// classification below.
	if f.Mailbox != "" {
		return KindMailboxTakeover
	}
	// Some authenticated-mail findings route bare cPanel-local accounts to
	// TenantID instead of Mailbox. Keep those in mailbox_takeover without
	// sweeping domain/config mail checks or PHP relay findings into it.
	if isMailboxTakeoverCheck(check) {
		return KindMailboxTakeover
	}

	// Host integrity -- daemon/kernel-level signals that indicate the
	// host itself is compromised, not a single tenant. Listed
	// explicitly so account-attributed checks that share a substring
	// (e.g. suspicious_crontab on a per-user spool) stay in the
	// tenant bucket.
	if isHostIntegrityCheck(check) {
		return KindHostIntegrityRisk
	}

	// Post-exploit process -- exe under ephemeral paths is a strong
	// indicator of staged-then-executed payloads (cryptominers, reverse
	// shells) regardless of which tenant owns the parent.
	if f.Process != nil && (strings.HasPrefix(f.Process.Exe, "/tmp/") ||
		strings.HasPrefix(f.Process.Exe, "/var/tmp/") ||
		strings.HasPrefix(f.Process.Exe, "/dev/shm/")) {
		return KindPostExploitProcess
	}

	// Inbound web attack -- a finding that would correlate on the source
	// IP alone (no tenant, domain, mailbox, or process actor) is an
	// external IP probing the web stack or flagged as an attacker by
	// reputation, not a compromised tenant. Route it to web_attack so it
	// does not inflate the account-compromise count or inherit the long
	// account-compromise retention.
	if (isInboundWebAttackCheck(check) || isRemoteIPThreatCheck(check)) && isRemoteIPKeyed(f) {
		return KindWebAttack
	}

	// Default -- account-scoped web compromise. Most CSM findings are
	// tenant-attributed web/PHP issues, so this fallback matches the
	// modal incident shape operators see.
	return KindWebAccountCompromise
}

// isRemoteIPKeyed reports whether a finding would correlate on its source
// IP alone -- i.e. it has no account (tenant, cPanel user, process
// account, or /home/<account>/ path), no domain, no mailbox, and no
// stable process actor (UID/PID). It mirrors KeyFor's RemoteIP fallback
// without calling KeyFor (KeyFor depends on ClassifyKind, so the reverse
// call would recurse). Callers reach this only after the host-integrity,
// mailbox, and post-exploit-process tiers have been ruled out.
func isRemoteIPKeyed(f alert.Finding) bool {
	if strings.TrimSpace(f.SourceIP) == "" {
		return false
	}
	mailbox, domain := canonicalizeMailboxDomain(f.Mailbox, f.Domain)
	if mailbox != "" || domain != "" {
		return false
	}
	if f.TenantID != "" || f.CPUser != "" {
		return false
	}
	if f.Process != nil && f.Process.Account != "" {
		return false
	}
	if accountFromHomePath(f.FilePath) != "" {
		return false
	}
	if f.Process != nil && (f.Process.UID != 0 || f.Process.PID != 0) {
		return false
	}
	return true
}

// isRemoteIPThreatCheck covers remote-IP reputation / threat-score signals
// that flag an attacking source IP rather than a compromised tenant. Like
// inbound web attacks these correlate on the source IP alone, so they belong
// in web_attack with attacker-grade retention, not the account-compromise
// bucket. Add future remote-IP reputation checks here.
func isRemoteIPThreatCheck(check string) bool {
	switch strings.ToLower(strings.TrimSpace(check)) {
	case "ip_reputation", "local_threat_score":
		return true
	default:
		return false
	}
}

func isInboundWebAttackCheck(check string) bool {
	check = strings.ToLower(strings.TrimSpace(check))
	if strings.HasPrefix(check, "http_") || strings.HasPrefix(check, "modsec_") {
		return true
	}
	switch check {
	case "admin_panel_bruteforce",
		"wp_login_bruteforce",
		"wp_user_enumeration",
		"xmlrpc_abuse",
		"waf_attack_blocked",
		"api_auth_failure",
		"api_auth_failure_realtime",
		"webmail_bruteforce",
		"webmail_login_realtime",
		"whm_login_realtime",
		"whm_unauth_scripts_realtime":
		return true
	default:
		return false
	}
}

// hostIntegrityChecks lists check names whose scope is the host itself
// (kernel modules, system daemon configs, root-owned credential stores)
// rather than a single tenant. Findings matching one of these jump
// straight to KindHostIntegrityRisk so incident severity reflects the
// blast radius.
var hostIntegrityChecks = map[string]bool{
	"bulk_password_change":    true,
	"sensitive_file_write":    true,
	"sensitive_file_modified": true,
	"fake_kernel_thread":      true,
	"auditd_disabled":         true,
	"modsec_disabled":         true,
	"shadow_change":           true,
	"sshd_config_change":      true,
	"root_password_change":    true,
	"uid0_account":            true,
	"suid_binary":             true,
	"bad_asn_outbound":        true,
	"kernel_module":           true,
	"crontab_change":          true,
	"crond_change":            true,
}

func isHostIntegrityCheck(check string) bool {
	return hostIntegrityChecks[strings.ToLower(strings.TrimSpace(check))]
}

func isMailboxTakeoverCheck(check string) bool {
	if strings.HasPrefix(check, "smtp_") || strings.HasPrefix(check, "sasl_") ||
		strings.HasPrefix(check, "mail_") {
		return true
	}

	switch check {
	case "email_auth_failure_realtime",
		"email_cloud_relay_abuse",
		"email_compromised_account",
		"email_credential_leak",
		"email_rate_critical",
		"email_rate_warning",
		"email_spam_outbreak",
		"email_suspicious_geo":
		return true
	default:
		return false
	}
}
