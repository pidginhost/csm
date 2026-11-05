package state

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

// The authenticated FTP login name feeds customer history only. The public
// finding JSON (API, events, webhooks, phpanel) never carries it, while a
// finding parked at shutdown keeps it for the replay.
func TestPendingFindingsKeepLoginAccount(t *testing.T) {
	f := alert.Finding{Check: "ftp_login", Severity: alert.Warning, SourceIP: "203.0.113.94",
		LoginAccount: "office@example.com", Timestamp: time.Now()}
	public, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(public), "office@example.com") || strings.Contains(string(public), "login_account") {
		t.Fatalf("public finding JSON carries the login name: %s", public)
	}

	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if err = st.AppendPendingFindings([]alert.Finding{f}); err != nil {
		t.Fatal(err)
	}
	got, err := st.TakePendingFindings()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].LoginAccount != f.LoginAccount {
		t.Fatalf("replayed findings = %+v, want the login name", got)
	}
	without := f
	without.LoginAccount = ""
	if pendingIdentity([]alert.Finding{f}) == pendingIdentity([]alert.Finding{without}) {
		t.Fatal("pending batch identity ignores the login name")
	}
}
