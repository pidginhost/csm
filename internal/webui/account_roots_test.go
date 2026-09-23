package webui

import (
	"encoding/json"
	"errors"
	"html/template"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

// Accounts live under the platform's account roots (/home on cPanel,
// /var/www/vhosts on Plesk), not only /home.
func TestAccountDetailMatchesEveryAccountRoot(t *testing.T) {
	s := newTestServer(t, "tok")
	rootA, rootB := t.TempDir(), t.TempDir()
	s.accountRoots = func() []string { return []string{rootA, rootB} }
	path := filepath.Join(rootB, "alice", "httpdocs", "x.php")
	now := time.Now()
	findings := []alert.Finding{
		{Severity: alert.High, Check: "webshell", Message: "Webshell in " + path, FilePath: path, Timestamp: now},
		{Severity: alert.High, Check: "webshell", Message: "Webshell in " + filepath.Join(rootB, "bob", "x.php"), Timestamp: now},
	}
	s.store.SetLatestFindings(findings)
	s.store.AppendHistory(findings)

	w := httptest.NewRecorder()
	s.apiAccountDetail(w, httptest.NewRequest(http.MethodGet, "/?name=alice", nil))
	var data struct {
		Findings []struct{ Message string } `json:"findings"`
		History  []struct{ Message string } `json:"history"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &data); err != nil {
		t.Fatal(err)
	}
	if len(data.Findings) != 1 || !strings.Contains(data.Findings[0].Message, path) {
		t.Errorf("findings = %+v, want alice's finding under the second root", data.Findings)
	}
	if len(data.History) != 1 {
		t.Errorf("history = %+v, want alice's finding under the second root", data.History)
	}
}

// The account page lists quarantined files from the quarantine directory the
// rest of the UI uses, not a second hard-coded copy of its path.
func TestAccountDetailReadsTheQuarantineDirectory(t *testing.T) {
	s := newTestServer(t, "tok")
	old := quarantineDir
	quarantineDir = t.TempDir()
	t.Cleanup(func() { quarantineDir = old })
	root := t.TempDir()
	s.accountRoots = func() []string { return []string{root} }
	meta, err := json.Marshal(map[string]any{
		"original_path":  filepath.Join(root, "alice", "public_html", "shell.php"),
		"size":           10,
		"reason":         "webshell",
		"quarantined_at": time.Now().Format(time.RFC3339),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(quarantineDir, "20260923-000000_shell.php.meta"), meta, 0o600); err != nil {
		t.Fatal(err)
	}

	w := httptest.NewRecorder()
	s.apiAccountDetail(w, httptest.NewRequest(http.MethodGet, "/?name=alice", nil))
	var data struct {
		Quarantined []struct {
			OriginalPath string `json:"original_path"`
		} `json:"quarantined"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &data); err != nil {
		t.Fatal(err)
	}
	if len(data.Quarantined) != 1 {
		t.Fatalf("quarantined = %+v, want alice's file", data.Quarantined)
	}
}

func TestAccountPageShowsTheAccountHome(t *testing.T) {
	s := newTestServerWithTemplates(t, "tok")
	rootA, rootB := t.TempDir(), t.TempDir()
	if err := os.Mkdir(filepath.Join(rootB, "alice"), 0o700); err != nil {
		t.Fatal(err)
	}
	s.accountRoots = func() []string { return []string{rootA, rootB} }
	s.templates["account.html"] = template.Must(template.New("account.html").Parse("{{.HomeDir}}"))

	w := httptest.NewRecorder()
	s.handleAccount(w, httptest.NewRequest(http.MethodGet, "/account?name=alice", nil))
	if got, want := strings.TrimSpace(w.Body.String()), filepath.Join(rootB, "alice"); got != want {
		t.Fatalf("HomeDir = %q, want %q", got, want)
	}
}

// The scan dropdown offers the accounts a server-wide scan would cover.
func TestAPIAccountsListsTheScanAccounts(t *testing.T) {
	s := newTestServer(t, "tok")
	s.scanAccounts = func(*config.Config) ([]string, error) { return []string{"alice", "bob"}, nil }
	w := httptest.NewRecorder()
	s.apiAccounts(w, httptest.NewRequest(http.MethodGet, "/api/v1/accounts", nil))
	var got []string
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if strings.Join(got, ",") != "alice,bob" {
		t.Fatalf("accounts = %v, want alice,bob", got)
	}

	s.scanAccounts = func(*config.Config) ([]string, error) { return nil, errors.New("registry unreadable") }
	w = httptest.NewRecorder()
	s.apiAccounts(w, httptest.NewRequest(http.MethodGet, "/api/v1/accounts", nil))
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 when the inventory cannot be read", w.Code)
	}
}
