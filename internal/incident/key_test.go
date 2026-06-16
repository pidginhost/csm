package incident

import (
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/processctx"
)

func TestKeyForAccountFinding(t *testing.T) {
	f := alert.Finding{
		Check:     "wp_login_bruteforce",
		Message:   "test",
		TenantID:  "alice",
		Timestamp: time.Now(),
	}
	k := KeyFor(f)
	if k.Account != "alice" {
		t.Errorf("Account: want alice, got %q", k.Account)
	}
	if k.Mailbox != "" {
		t.Errorf("Mailbox: want empty for non-mail finding, got %q", k.Mailbox)
	}
}

func TestKeyForMailboxFinding(t *testing.T) {
	f := alert.Finding{
		Check:    "outbound_spam",
		Mailbox:  "alice@example.com",
		Domain:   "example.com",
		TenantID: "alice",
	}
	k := KeyFor(f)
	if k.Mailbox != "alice@example.com" {
		t.Errorf("Mailbox: %q", k.Mailbox)
	}
	// Domain is intentionally dropped when Mailbox already includes
	// it (or is the full @-form), so the canonical key matches
	// regardless of which emit convention the caller used.
	if k.Domain != "" {
		t.Errorf("Domain expected dropped after canonicalisation, got %q", k.Domain)
	}
}

func TestKeyForProcessFinding(t *testing.T) {
	f := alert.Finding{
		Check: "outbound_connection",
		Process: &processctx.ProcessContext{
			PID:     4242,
			UID:     1001,
			Account: "alice",
		},
	}
	k := KeyFor(f)
	if k.Account != "alice" {
		t.Errorf("Account from Process.Account: %q", k.Account)
	}
	// UID is dropped from the key when Account is set so two
	// findings about the same account from different processes do
	// not split into separate incidents.
	if k.UID != 0 {
		t.Errorf("UID expected dropped when Account is set, got %d", k.UID)
	}
	if k.PID != 0 {
		t.Errorf("PID should not split account/UID key, got %d", k.PID)
	}
}

func TestKeyForProcessPIDFallback(t *testing.T) {
	f := alert.Finding{
		Check:   "outbound_connection",
		Process: &processctx.ProcessContext{PID: 4242},
	}
	k := KeyFor(f)
	if k.PID != 4242 {
		t.Errorf("PID fallback: want 4242, got %d", k.PID)
	}
}

func TestKeyForFanotifyFindingExtractsAccountFromPath(t *testing.T) {
	f := alert.Finding{
		Check:    "webshell_detected",
		FilePath: "/home/alice/public_html/shell.php",
	}
	k := KeyFor(f)
	if k.Account != "alice" {
		t.Errorf("Account from /home/<acct>/...: want alice, got %q", k.Account)
	}
}

func TestKeyForCpanelHomePathExtractsAccount(t *testing.T) {
	f := alert.Finding{
		Check:    "webshell_detected",
		FilePath: "/home2/bob/public_html/x.php",
	}
	k := KeyFor(f)
	if k.Account != "bob" {
		t.Errorf("Account from /home2/<acct>/...: want bob, got %q", k.Account)
	}
}

func TestKeyForUnattributableFindingReturnsEmpty(t *testing.T) {
	f := alert.Finding{Check: "system_load", Message: "system load high"}
	k := KeyFor(f)
	if !k.IsEmpty() {
		t.Errorf("expected empty key for system finding, got %+v", k)
	}
}

func TestKeyForHostIntegrityFindingUsesHostKey(t *testing.T) {
	f := alert.Finding{Check: "kernel_module", Message: "new module loaded"}
	k := KeyFor(f)
	if k.Host != "host" {
		t.Fatalf("Host = %q, want host", k.Host)
	}
	if k.Account != "" || k.Domain != "" || k.Mailbox != "" || k.RemoteIP != "" || k.UID != 0 || k.PID != 0 {
		t.Fatalf("host-integrity key must not carry tenant/process fields: %+v", k)
	}
}

func TestKeyForHostIntegrityIgnoresAccountAttribution(t *testing.T) {
	f := alert.Finding{
		Check:    "suid_binary",
		FilePath: "/home/alice/bin/helper",
		TenantID: "alice",
	}
	k := KeyFor(f)
	if k.Host != "host" {
		t.Fatalf("host-integrity key = %+v, want Host=host", k)
	}
	if k.Account != "" {
		t.Fatalf("host-integrity finding must not split by account, got %+v", k)
	}
}

// PHP-relay findings carry the cPanel user in CPUser rather than TenantID;
// without a fallback they would drop on the floor of the correlator. Account
// must be populated when CPUser is the only attribution available.
func TestKeyForCPUserFallback(t *testing.T) {
	f := alert.Finding{
		Check:  "email_php_relay_abuse",
		CPUser: "alice",
	}
	k := KeyFor(f)
	if k.Account != "alice" {
		t.Errorf("Account from CPUser: want alice, got %q", k.Account)
	}
}

func TestKeyForSourceIPFallback(t *testing.T) {
	f := alert.Finding{
		Check:    "smtp_probe_abuse",
		SourceIP: "203.0.113.44",
	}
	k := KeyFor(f)
	if k.RemoteIP != "203.0.113.44" {
		t.Errorf("RemoteIP from SourceIP: want 203.0.113.44, got %q", k.RemoteIP)
	}
}

func TestKeyForSourceIPDoesNotSplitMailboxKey(t *testing.T) {
	f := alert.Finding{
		Check:    "email_compromised_account",
		Mailbox:  "alice@example.com",
		Domain:   "example.com",
		SourceIP: "203.0.113.44",
	}
	k := KeyFor(f)
	if k.RemoteIP != "" {
		t.Errorf("RemoteIP should be empty when mailbox/domain identify the incident, got %q", k.RemoteIP)
	}
	// Mailbox keeps the full @-form; Domain is dropped because it is
	// already encoded in Mailbox after canonicalisation.
	if k.Mailbox != "alice@example.com" || k.Domain != "" {
		t.Errorf("mail key = %+v", k)
	}
}

// TenantID must win over CPUser so explicit tenant attribution is not
// silently overridden by the cPanel user shadow field.
func TestKeyForTenantIDBeatsCPUser(t *testing.T) {
	f := alert.Finding{
		Check:    "email_php_relay_abuse",
		TenantID: "tenant-a",
		CPUser:   "alice",
	}
	k := KeyFor(f)
	if k.Account != "tenant-a" {
		t.Errorf("Account: want tenant-a (TenantID wins), got %q", k.Account)
	}
}
