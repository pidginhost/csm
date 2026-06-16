package incident

import (
	"strings"

	"github.com/pidginhost/csm/internal/alert"
)

// ClassifyKind returns the incident Kind for a Finding using rule
// precedence: host-integrity signals first, then inbound attacks keyed on the
// attacker IP (web_attack, mailbox_bruteforce), then mailbox-takeover signals,
// then ephemeral-path process exec, then remote-IP reputation, then the
// account-scoped web-compromise default.
func ClassifyKind(f alert.Finding) Kind {
	check := strings.ToLower(f.Check)
	hasAttacker := strings.TrimSpace(f.SourceIP) != ""

	// Host integrity -- daemon/kernel-level signals whose blast radius is
	// the host itself, not a single tenant or an inbound attacker. Listed
	// explicitly so account-attributed checks that share a substring
	// (e.g. suspicious_crontab on a per-user spool) stay in the tenant
	// bucket.
	if isHostIntegrityCheck(check) {
		return KindHostIntegrityRisk
	}

	// Inbound attack keyed on the attacker IP. A defended web hit (WAF
	// block, scanner probe, login brute-force) or a failed mailbox login
	// names a victim domain/account/mailbox, but that is the attack
	// target, not evidence the account is compromised. Classify by the
	// attacker so defended traffic does not inflate the compromise /
	// takeover buckets or inherit their long retention. Requires an
	// attacker IP to key on; without one the finding falls through to the
	// account-scoped tiers below. Genuine compromise is recognised by the
	// on-disk and behavioural signals handled lower down, not by inbound
	// hits.
	if hasAttacker {
		if isMailAuthAttackCheck(check) {
			return KindMailboxBruteforce
		}
		if isInboundWebAttackCheck(check) {
			return KindWebAttack
		}
	}

	// Mailbox takeover -- a Mailbox attribute or a post-authentication
	// mail-abuse check name. Mailbox attribution is the strongest single
	// tenant signal so it wins over the account-scoped default below. Some
	// authenticated-mail findings route bare cPanel-local accounts to
	// TenantID instead of Mailbox; the check-name list keeps those here
	// without sweeping in domain/config mail checks or PHP relay findings.
	if f.Mailbox != "" {
		return KindMailboxTakeover
	}
	if isMailboxTakeoverCheck(check) {
		return KindMailboxTakeover
	}

	// Post-exploit process -- exe under ephemeral paths is a strong
	// indicator of staged-then-executed payloads (cryptominers, reverse
	// shells) regardless of which tenant owns the parent.
	if f.Process != nil && (strings.HasPrefix(f.Process.Exe, "/tmp/") ||
		strings.HasPrefix(f.Process.Exe, "/var/tmp/") ||
		strings.HasPrefix(f.Process.Exe, "/dev/shm/")) {
		return KindPostExploitProcess
	}

	// Remote-IP reputation / threat-score with no victim attribution -- an
	// attacking source IP flagged by reputation, not a compromised tenant.
	// Kept on the strict remote-IP-keyed gate: a reputation hit tied to an
	// account is about that account, not an anonymous attacker.
	if isRemoteIPThreatCheck(check) && isRemoteIPKeyed(f) {
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

// isMailAuthAttackCheck covers failed mail-authentication and pre-auth mail
// probe signals. These are attacker attempts keyed on the source IP, not
// evidence that the targeted mailbox was taken over.
func isMailAuthAttackCheck(check string) bool {
	switch strings.ToLower(strings.TrimSpace(check)) {
	case "email_auth_failure_realtime",
		"mail_account_spray",
		"mail_bruteforce",
		"mail_subnet_spray",
		"smtp_account_spray",
		"smtp_bruteforce",
		"smtp_probe_abuse",
		"smtp_subnet_spray":
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
	switch check {
	case "email_cloud_relay_abuse",
		"email_compromised_account",
		"email_credential_leak",
		"email_rate_critical",
		"email_rate_warning",
		"email_spam_outbreak",
		"email_suspicious_geo",
		"mail_account_compromised",
		"mail_per_account",
		"smtp_brute_failure_then_success":
		return true
	default:
		return false
	}
}
