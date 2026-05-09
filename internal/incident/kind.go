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

	// Mailbox takeover -- any check with a Mailbox attribute or
	// SMTP/SASL bruteforce check name. Mailbox attribution is the
	// strongest single signal so it wins over generic check-name
	// classification below.
	if f.Mailbox != "" {
		return KindMailboxTakeover
	}
	// Mail-stack check name prefixes always classify as mailbox takeover,
	// even when the finding has no Mailbox field (bare cPanel-local
	// accounts route to TenantID; SourceIP-only modsec/probe findings
	// have no mailbox at all). Without this, operators see a mail-stack
	// brute-force labelled "web_account_compromise".
	if strings.HasPrefix(check, "smtp_") || strings.HasPrefix(check, "sasl_") ||
		strings.HasPrefix(check, "email_") || strings.HasPrefix(check, "mail_") {
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
