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
		"bad_asn_outbound",
		"kernel_module",
		"crontab_change",
		"crond_change",
		"mail_auth_backend_degraded",
	} {
		got := ClassifyKind(alert.Finding{Check: check, SourceIP: "203.0.113.7"})
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

// Post-authentication mail abuse classifies as mailbox_takeover even when the
// finding lacks a Mailbox attribute. Bare cPanel-local accounts route to
// TenantID. Failed-login and pre-auth probe signals are handled separately as
// mailbox_bruteforce; an attack attempt is not a takeover.
func TestClassifyKindMailAuthChecksMapToMailboxTakeover(t *testing.T) {
	mailChecks := []string{
		"email_compromised_account",
		"email_credential_leak",
		"email_rate_warning",
		"email_rate_critical",
		"email_suspicious_geo",
		"email_cloud_relay_abuse",
		"email_spam_outbreak",
		"mail_account_compromised",
		"mail_per_account",
		"smtp_brute_failure_then_success",
	}
	for _, check := range mailChecks {
		got := ClassifyKind(alert.Finding{Check: check, TenantID: "alice"})
		if got != KindMailboxTakeover {
			t.Errorf("check %q: got %v, want mailbox_takeover", check, got)
		}
	}
}

// A failed mailbox login is a brute-force attempt, not a takeover. It carries
// the targeted mailbox (the victim) and the attacker source IP; classify by
// the attacker so repeated failures from one IP collapse into a single
// mailbox_bruteforce incident with short attacker-grade retention. The victim
// mailbox/account attribution must not promote it to mailbox_takeover.
func TestClassifyKindMailboxBruteforce(t *testing.T) {
	cases := []alert.Finding{
		{Check: "email_auth_failure_realtime", SourceIP: "203.0.113.7", Mailbox: "bob@example.com"},
		{Check: "email_auth_failure_realtime", SourceIP: "203.0.113.7", TenantID: "alice"},
		{Check: "email_auth_failure_realtime", SourceIP: "203.0.113.7", Domain: "example.com"},
		{Check: "email_auth_failure_realtime", SourceIP: "203.0.113.7"},
		{Check: "mail_bruteforce", SourceIP: "203.0.113.7"},
		{Check: "mail_subnet_spray", SourceIP: "203.0.113.0/24"},
		{Check: "mail_account_spray", SourceIP: "203.0.113.7", Mailbox: "bob@example.com"},
		{Check: "smtp_bruteforce", SourceIP: "203.0.113.7"},
		{Check: "smtp_subnet_spray", SourceIP: "203.0.113.0/24"},
		{Check: "smtp_account_spray", SourceIP: "203.0.113.7", Mailbox: "bob@example.com"},
		{Check: "smtp_probe_abuse", SourceIP: "203.0.113.7"},
	}
	for _, f := range cases {
		if got := ClassifyKind(f); got != KindMailboxBruteforce {
			t.Errorf("%+v: got %v, want mailbox_bruteforce", f, got)
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
	for _, check := range []string{
		"modsec_warning_realtime",
		"modsec_csm_block_escalation",
		"wp_login_bruteforce",
		"http_ua_spoof",
		"waf_attack_blocked",
		"api_auth_failure",
		"api_auth_failure_realtime",
		"webmail_bruteforce",
		"whm_unauth_scripts_realtime",
	} {
		got := ClassifyKind(alert.Finding{Check: check, SourceIP: "203.0.113.7"})
		if got != KindWebAttack {
			t.Errorf("check %q with only a source IP: got %v, want web_attack", check, got)
		}
	}
}

func TestClassifyKindNonWebRemoteIPOnlyNotWebAttack(t *testing.T) {
	for _, check := range []string{"pam_bruteforce", "ssh_bruteforce", "c2_connection", "backdoor_port"} {
		got := ClassifyKind(alert.Finding{Check: check, SourceIP: "203.0.113.7"})
		if got == KindWebAttack {
			t.Errorf("non-web check %q with only a source IP classified as web_attack", check)
		}
	}
}

func TestClassifyKindStateChangingAccountActionNotWebAttack(t *testing.T) {
	got := ClassifyKind(alert.Finding{Check: "cpanel_file_upload_realtime", SourceIP: "203.0.113.7"})
	if got != KindWebAccountCompromise {
		t.Errorf("cpanel_file_upload_realtime with only a source IP: got %v, want web_account_compromise", got)
	}
}

// Remote-IP reputation/threat-score signals flag an attacking source IP, not
// a compromised tenant, so they classify as web_attack (24h window) rather
// than the 7-day web_account_compromise bucket.
func TestClassifyKindRemoteIPThreatScoreIsWebAttack(t *testing.T) {
	for _, check := range []string{"ip_reputation", "local_threat_score"} {
		got := ClassifyKind(alert.Finding{Check: check, Severity: alert.Critical, SourceIP: "203.0.113.7"})
		if got != KindWebAttack {
			t.Errorf("%s with only a source IP: got %v, want web_attack", check, got)
		}
	}
}

// An inbound web attack classifies as web_attack even when the finding names
// a victim domain, account, or mailbox. A ModSecurity block or scanner probe
// records the targeted vhost in the Host header, but that is the attack
// target, not evidence the account is compromised. Classify by the attacker
// source IP so defended inbound traffic does not inflate the
// account-compromise count or inherit the 7-day review window.
func TestClassifyKindAttributedInboundAttackIsWebAttack(t *testing.T) {
	cases := []alert.Finding{
		{Check: "modsec_block_realtime", SourceIP: "203.0.113.7", Domain: "example.com"},
		{Check: "modsec_warning_realtime", SourceIP: "203.0.113.7", TenantID: "alice"},
		{Check: "modsec_csm_block_escalation", SourceIP: "203.0.113.7", CPUser: "alice"},
		{Check: "modsec_warning_realtime", SourceIP: "203.0.113.7", Mailbox: "bob@example.com"},
		{Check: "http_ua_spoof", SourceIP: "203.0.113.7", Domain: "example.com"},
		{Check: "wp_login_bruteforce", SourceIP: "203.0.113.7", Domain: "example.com"},
	}
	for _, f := range cases {
		if got := ClassifyKind(f); got != KindWebAttack {
			t.Errorf("%+v: got %v, want web_attack", f, got)
		}
	}
}

// Signals that are not inbound web attacks stay out of web_attack even with a
// source IP: reputation/threat-score with account attribution is no longer
// remote-IP-keyed, and on-disk evidence (a webshell under the account home)
// is a genuine compromise.
func TestClassifyKindNotInboundAttackNotWebAttack(t *testing.T) {
	cases := []alert.Finding{
		{Check: "ip_reputation", SourceIP: "203.0.113.7", TenantID: "alice"},
		{Check: "local_threat_score", SourceIP: "203.0.113.7", Domain: "example.com"},
		{Check: "webshell_detected", SourceIP: "203.0.113.7", FilePath: "/home/alice/public_html/x.php"},
	}
	for _, f := range cases {
		if got := ClassifyKind(f); got == KindWebAttack {
			t.Errorf("%+v: classified as web_attack, want a non-attack kind", f)
		}
	}
}

// On-disk and behavioural evidence keeps a finding in web_account_compromise:
// a webshell under the account home is a real tenant compromise, not an
// inbound probe, and warrants the longer review window.
func TestClassifyKindWebCompromiseForOnDiskEvidence(t *testing.T) {
	cases := []alert.Finding{
		{Check: "webshell_detected", SourceIP: "203.0.113.7", FilePath: "/home/alice/public_html/x.php"},
		{Check: "suspicious_php_content", TenantID: "alice"},
		{Check: "php_in_uploads_realtime", TenantID: "alice"},
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

func TestCorrelatorClassifiesRemoteIPReputationAsWebAttack(t *testing.T) {
	for _, check := range []string{"ip_reputation", "local_threat_score"} {
		t.Run(check, func(t *testing.T) {
			c := newTestCorrelator()
			f := alert.Finding{Check: check, Severity: alert.Critical, SourceIP: "203.0.113.7"}
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
		})
	}
}

// A ModSecurity block that names a victim domain still opens a single
// web_attack incident keyed on the attacker IP, not a per-domain
// account-compromise incident. This is the core fix: defended inbound traffic
// against a hosted vhost is an attack on that vhost, keyed by who is attacking.
func TestCorrelatorClassifiesAttributedModsecAsWebAttackKeyedByIP(t *testing.T) {
	c := newTestCorrelator()
	f := alert.Finding{Check: "modsec_block_realtime", Severity: alert.Critical, SourceIP: "203.0.113.7", Domain: "example.com"}
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
	if inc.Account != "" {
		t.Errorf("web_attack incident must not be account-scoped, got Account=%q", inc.Account)
	}
}

// A failed mailbox login opens a mailbox_bruteforce incident keyed on the
// attacker IP, collapsing brute-force attempts across mailboxes from one
// source into a single incident instead of a per-mailbox takeover.
func TestCorrelatorClassifiesFailedMailAuthAsMailboxBruteforceKeyedByIP(t *testing.T) {
	c := newTestCorrelator()
	f := alert.Finding{Check: "email_auth_failure_realtime", Severity: alert.High, SourceIP: "203.0.113.7", Mailbox: "bob@example.com"}
	id, _, _ := c.OnFinding(f)
	inc, ok := c.Get(id)
	if !ok {
		t.Fatal("expected an incident to be created")
	}
	if inc.Kind != KindMailboxBruteforce {
		t.Errorf("Kind: got %v, want mailbox_bruteforce", inc.Kind)
	}
	if inc.CorrelationKey == nil || inc.CorrelationKey.RemoteIP != "203.0.113.7" {
		t.Errorf("expected incident keyed on remote IP, got %+v", inc.CorrelationKey)
	}
}

func TestCorrelatorClassifiesAggregateMailAuthAsMailboxBruteforce(t *testing.T) {
	c := newTestCorrelator()
	f := alert.Finding{Check: "smtp_bruteforce", Severity: alert.Critical, SourceIP: "203.0.113.7"}
	id, _, _ := c.OnFinding(f)
	inc, ok := c.Get(id)
	if !ok {
		t.Fatal("expected an incident to be created")
	}
	if inc.Kind != KindMailboxBruteforce {
		t.Errorf("Kind: got %v, want mailbox_bruteforce", inc.Kind)
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
