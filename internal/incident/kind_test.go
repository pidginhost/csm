package incident

import (
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/processctx"
)

func TestClassifyKindMailboxTakeover(t *testing.T) {
	got := ClassifyKind(alert.Finding{Check: "smtp_brute_failure_then_success", Mailbox: "alice@example.com"})
	if got != KindMailboxTakeover {
		t.Errorf("got %v", got)
	}
}

func TestClassifyKindWebAccountCompromise(t *testing.T) {
	for _, check := range []string{"webshell_detected", "wp_login_bruteforce", "exploit_revslider", "php_relay_abuse"} {
		got := ClassifyKind(alert.Finding{Check: check, TenantID: "alice"})
		if got != KindWebAccountCompromise {
			t.Errorf("check %q: got %v, want web_account_compromise", check, got)
		}
	}
}

func TestClassifyKindPostExploitProcess(t *testing.T) {
	got := ClassifyKind(alert.Finding{
		Check:   "outbound_connection",
		Process: &processctx.ProcessContext{Exe: "/tmp/.x/miner"},
	})
	if got != KindPostExploitProcess {
		t.Errorf("/tmp/ exe should classify as post_exploit_process, got %v", got)
	}
}

func TestClassifyKindHostIntegrityRisk(t *testing.T) {
	for _, check := range []string{"sensitive_file_write", "fake_kernel_thread", "auditd_disabled"} {
		got := ClassifyKind(alert.Finding{Check: check})
		if got != KindHostIntegrityRisk {
			t.Errorf("check %q: got %v, want host_integrity_risk", check, got)
		}
	}
}

func TestClassifyKindFallback(t *testing.T) {
	got := ClassifyKind(alert.Finding{Check: "unknown_check", TenantID: "alice"})
	if got != KindWebAccountCompromise {
		t.Errorf("default for account-attributed unknown check should be web_account_compromise, got %v", got)
	}
}

// Mail-stack auth checks must classify as mailbox_takeover even when the
// finding lacks a Mailbox attribute (bare cPanel-local accounts and
// SourceIP-only modes). Otherwise the kind label "web_account_compromise"
// misleads operators about a mail-stack incident.
func TestClassifyKindMailAuthChecksMapToMailboxTakeover(t *testing.T) {
	mailChecks := []string{
		"email_auth_failure_realtime",
		"email_compromised_account",
		"email_credential_leak",
		"email_dkim_failure",
		"email_spf_rejection",
		"email_rate_warning",
		"email_rate_critical",
		"email_suspicious_geo",
		"email_cloud_relay_abuse",
		"email_php_relay_abuse",
		"email_spam_outbreak",
		"mail_bruteforce",
		"mail_subnet_spray",
		"mail_account_spray",
		"mail_account_compromised",
	}
	for _, check := range mailChecks {
		got := ClassifyKind(alert.Finding{Check: check, TenantID: "alice"})
		if got != KindMailboxTakeover {
			t.Errorf("check %q: got %v, want mailbox_takeover", check, got)
		}
	}
}

func TestCorrelatorAssignsKindOnCreate(t *testing.T) {
	c := newTestCorrelator()
	f := alert.Finding{Check: "fake_kernel_thread", Severity: alert.Critical, TenantID: "root"}
	id, _, _ := c.OnFinding(f)
	inc, _ := c.Get(id)
	if inc.Kind != KindHostIntegrityRisk {
		t.Errorf("Kind: got %v, want host_integrity_risk", inc.Kind)
	}
}
