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
	// explicitly to avoid sweeping unrelated checks into this bucket.
	for _, hi := range []string{"sensitive_file_write", "fake_kernel_thread", "auditd_disabled", "modsec_disabled"} {
		if check == hi {
			return KindHostIntegrityRisk
		}
	}

	// Post-exploit process -- exe under ephemeral paths is a strong
	// indicator of staged-then-executed payloads (cryptominers, reverse
	// shells) regardless of which tenant owns the parent.
	if f.Process != nil && (strings.HasPrefix(f.Process.Exe, "/tmp/") ||
		strings.HasPrefix(f.Process.Exe, "/var/tmp/") ||
		strings.HasPrefix(f.Process.Exe, "/dev/shm/")) {
		return KindPostExploitProcess
	}

	// Default -- account-scoped web compromise. Most CSM findings are
	// tenant-attributed web/PHP issues, so this fallback matches the
	// modal incident shape operators see.
	return KindWebAccountCompromise
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
