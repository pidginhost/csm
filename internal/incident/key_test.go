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
	if k.Domain != "example.com" {
		t.Errorf("Domain: %q", k.Domain)
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
	if k.UID != 1001 {
		t.Errorf("UID: want 1001, got %d", k.UID)
	}
	if k.PID != 4242 {
		t.Errorf("PID: want 4242, got %d", k.PID)
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
