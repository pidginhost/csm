package state

import (
	"encoding/json"
	"os"
	"path/filepath"
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
	path := st.path
	if err = st.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	st = reopened
	got, err := st.TakePendingFindings()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].LoginAccount != f.LoginAccount {
		t.Fatalf("replayed findings = %+v, want the login name", got)
	}
	public, err = json.Marshal(got[0])
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(public), f.LoginAccount) || strings.Contains(string(public), "login_account") {
		t.Fatalf("replayed public finding JSON carries the login name: %s", public)
	}
	without := f
	without.LoginAccount = ""
	if pendingIdentity([]alert.Finding{f}) == pendingIdentity([]alert.Finding{without}) {
		t.Fatal("pending batch identity ignores the login name")
	}
}

// An upgrade must also replay the login identity parked by the previous
// finding format, even when bounded details no longer contain that identity.
func TestPendingFindingsKeepStoredLoginAccount(t *testing.T) {
	for name, record := range map[string]string{
		"legacy":   `[{"check":"ftp_login","login_account":"office@example.com","details":"truncated"}]`,
		"internal": `[{"check":"ftp_login","response_login_account":"office@example.com","details":"truncated"}]`,
	} {
		t.Run(name, func(t *testing.T) {
			st, err := Open(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = st.Close() })
			if err = os.WriteFile(filepath.Join(st.path, pendingFindingsFile), []byte(record), 0o600); err != nil {
				t.Fatal(err)
			}
			got, err := st.TakePendingFindings()
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != 1 || got[0].LoginAccount != "office@example.com" {
				t.Fatalf("stored replay = %+v, want its authenticated login name", got)
			}
		})
	}
}
