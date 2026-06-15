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
	for _, check := range []string{"webshell_detected", "wp_login_bruteforce", "exploit_revslider", "php_relay_abuse", "email_php_relay_abuse"} {
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
	for _, check := range []string{
		"bulk_password_change",
		"sensitive_file_write",
		"sensitive_file_modified",
		"fake_kernel_thread",
		"auditd_disabled",
		"modsec_disabled",
		"shadow_change",
		"sshd_config_change",
		"root_password_change",
		"uid0_account",
		"suid_binary",
		"kernel_module",
		"crontab_change",
		"crond_change",
	} {
		got := ClassifyKind(alert.Finding{Check: check})
		if got != KindHostIntegrityRisk {
			t.Errorf("check %q: got %v, want host_integrity_risk", check, got)
		}
	}
}

// Tenant-attributed checks that look "system-adjacent" must NOT be swept
// into host_integrity_risk. A per-user crontab with a suspicious pattern
// is an account-compromise signal, not a host-scope kernel/daemon
// change. The classifier has to keep them in web_account_compromise.
func TestClassifyKindAccountScopedSystemAdjacentChecks(t *testing.T) {
	for _, check := range []string{"suspicious_crontab"} {
		got := ClassifyKind(alert.Finding{Check: check, TenantID: "alice"})
		if got != KindWebAccountCompromise {
			t.Errorf("check %q: got %v, want web_account_compromise", check, got)
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
// finding lacks a Mailbox attribute. Bare cPanel-local accounts route to
// TenantID, and source-IP-only auth probes still belong to the mail incident
// family.
func TestClassifyKindMailAuthChecksMapToMailboxTakeover(t *testing.T) {
	mailChecks := []string{
		"email_auth_failure_realtime",
		"email_compromised_account",
		"email_credential_leak",
		"email_rate_warning",
		"email_rate_critical",
		"email_suspicious_geo",
		"email_cloud_relay_abuse",
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

func TestClassifyKindDomainMailChecksStayWebAccountCompromise(t *testing.T) {
	for _, check := range []string{"email_dkim_failure", "email_spf_rejection"} {
		got := ClassifyKind(alert.Finding{Check: check, Domain: "example.com"})
		if got != KindWebAccountCompromise {
			t.Errorf("check %q: got %v, want web_account_compromise", check, got)
		}
	}
}

// Inbound attack attempts that carry only a remote IP (no tenant, domain,
// mailbox, or process actor) are not account compromises -- they are an
// external IP probing the web stack (modsec rule hits, CSM rule
// escalation). They must classify as web_attack so they get attacker-grade
// retention instead of the 7-day account-compromise window.
func TestClassifyKindWebAttackForRemoteIPOnly(t *testing.T) {
	for _, check := range []string{"modsec_warning_realtime", "modsec_csm_block_escalation", "wp_login_bruteforce"} {
		got := ClassifyKind(alert.Finding{Check: check, SourceIP: "203.0.113.7"})
		if got != KindWebAttack {
			t.Errorf("check %q with only a source IP: got %v, want web_attack", check, got)
		}
	}
}

// Any account/domain/mailbox attribution keeps a finding out of web_attack,
// even when it carries a source IP. (A mailbox attribution wins the earlier
// mailbox_takeover tier; the guarantee here is "not an anonymous inbound
// probe".)
func TestClassifyKindAccountAttributedNotWebAttack(t *testing.T) {
	cases := []alert.Finding{
		{Check: "modsec_warning_realtime", SourceIP: "203.0.113.7", TenantID: "alice"},
		{Check: "modsec_warning_realtime", SourceIP: "203.0.113.7", Domain: "example.com"},
		{Check: "modsec_warning_realtime", SourceIP: "203.0.113.7", Mailbox: "bob@example.com"},
		{Check: "modsec_warning_realtime", SourceIP: "203.0.113.7", CPUser: "alice"},
		{Check: "webshell_detected", SourceIP: "203.0.113.7", FilePath: "/home/alice/public_html/x.php"},
	}
	for _, f := range cases {
		if got := ClassifyKind(f); got == KindWebAttack {
			t.Errorf("%+v: classified as web_attack, want an account-attributed kind", f)
		}
	}
}

// Account-attributed web findings with no mailbox/host/process signal stay
// web_account_compromise: a real tenant signal warranting the longer review
// window, not an anonymous inbound probe.
func TestClassifyKindWebCompromiseForAccountAttributed(t *testing.T) {
	cases := []alert.Finding{
		{Check: "modsec_warning_realtime", SourceIP: "203.0.113.7", TenantID: "alice"},
		{Check: "modsec_warning_realtime", SourceIP: "203.0.113.7", Domain: "example.com"},
		{Check: "modsec_warning_realtime", SourceIP: "203.0.113.7", CPUser: "alice"},
		{Check: "webshell_detected", SourceIP: "203.0.113.7", FilePath: "/home/alice/public_html/x.php"},
	}
	for _, f := range cases {
		if got := ClassifyKind(f); got != KindWebAccountCompromise {
			t.Errorf("%+v: got %v, want web_account_compromise", f, got)
		}
	}
}

// A finding with no source IP and no account attribution cannot be
// remote-IP-keyed, so it stays web_account_compromise (the modal default).
func TestClassifyKindNoSourceIPStaysWebAccountCompromise(t *testing.T) {
	if got := ClassifyKind(alert.Finding{Check: "unknown_check"}); got != KindWebAccountCompromise {
		t.Errorf("no source IP, no account: got %v, want web_account_compromise", got)
	}
}

// A process-keyed finding (UID/PID actor, no account) is not remote-IP-keyed
// even when it carries a source IP, so it must not become web_attack.
func TestClassifyKindProcessKeyedNotWebAttack(t *testing.T) {
	got := ClassifyKind(alert.Finding{
		Check:    "outbound_connection",
		SourceIP: "203.0.113.7",
		Process:  &processctx.ProcessContext{UID: 99, PID: 1234},
	})
	if got == KindWebAttack {
		t.Errorf("process-keyed finding must not classify as web_attack, got %v", got)
	}
}

// A remote-IP-keyed inbound attack flows through the correlator into a
// single web_attack incident keyed on the source IP.
func TestCorrelatorClassifiesRemoteIPModsecAsWebAttack(t *testing.T) {
	c := newTestCorrelator()
	f := alert.Finding{Check: "modsec_csm_block_escalation", Severity: alert.Critical, SourceIP: "203.0.113.7"}
	id, _, _ := c.OnFinding(f)
	inc, ok := c.Get(id)
	if !ok {
		t.Fatal("expected an incident to be created")
	}
	if inc.Kind != KindWebAttack {
		t.Errorf("Kind: got %v, want web_attack", inc.Kind)
	}
	if inc.CorrelationKey == nil || inc.CorrelationKey.RemoteIP != "203.0.113.7" {
		t.Errorf("expected incident keyed on remote IP, got %+v", inc.CorrelationKey)
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
