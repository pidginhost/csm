package attackdb

import (
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

func TestClassify_SMTPChecksAsBruteForce(t *testing.T) {
	for _, check := range []string{"smtp_bruteforce", "smtp_subnet_spray"} {
		got := checkToAttack[check]
		if got != AttackBruteForce {
			t.Errorf("%q classified as %q, want %q", check, got, AttackBruteForce)
		}
	}
}

func TestClassify_MailChecksAsBruteForce(t *testing.T) {
	for _, check := range []string{"mail_bruteforce", "mail_subnet_spray", "mail_account_compromised"} {
		got := checkToAttack[check]
		if got != AttackBruteForce {
			t.Errorf("%q classified as %q, want %q", check, got, AttackBruteForce)
		}
	}
}

func TestClassify_AdminPanelBruteForceAsBruteForce(t *testing.T) {
	got := checkToAttack["admin_panel_bruteforce"]
	if got != AttackBruteForce {
		t.Errorf("admin_panel_bruteforce classified as %q, want %q", got, AttackBruteForce)
	}
}

func TestClassify_CredentialStuffingAsBruteForce(t *testing.T) {
	got := checkToAttack["credential_stuffing"]
	if got != AttackBruteForce {
		t.Errorf("credential_stuffing classified as %q, want %q", got, AttackBruteForce)
	}
}

func TestClassify_EmailAuthFailureRealtimeAsBruteForce(t *testing.T) {
	// Per-event dovecot/exim SMTP-AUTH failures must feed the attack DB so a
	// sustained mail brute force builds reputation even when the aggregated
	// smtp_bruteforce signal is absent. Sibling realtime auth checks
	// (api_auth_failure_realtime, ftp_auth_failure_realtime) are already
	// classified; this one was missing, so 1000s of mail-auth failures from a
	// single IP left it invisible to local_threat_score.
	got := checkToAttack["email_auth_failure_realtime"]
	if got != AttackBruteForce {
		t.Errorf("email_auth_failure_realtime classified as %q, want %q", got, AttackBruteForce)
	}
}

func TestRecordFinding_EmailAuthFailureBuildsReputation(t *testing.T) {
	db := newTestDB(t)
	ts := time.Date(2026, 6, 7, 5, 35, 0, 0, time.UTC)
	for i := 0; i < 20; i++ {
		db.RecordFinding(alert.Finding{
			Check:     "email_auth_failure_realtime",
			Message:   "Email authentication failure for florin from 203.0.113.7",
			Severity:  alert.High,
			Timestamp: ts.Add(time.Duration(i) * time.Minute),
		})
	}
	rec := db.LookupIP("203.0.113.7")
	if rec == nil {
		t.Fatal("mail auth failures did not create an attack-DB record")
	}
	if rec.EventCount != 20 {
		t.Errorf("EventCount = %d, want 20", rec.EventCount)
	}
	if rec.AttackCounts[AttackBruteForce] != 20 {
		t.Errorf("AttackCounts[brute_force] = %d, want 20", rec.AttackCounts[AttackBruteForce])
	}
}
