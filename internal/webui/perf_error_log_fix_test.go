package webui

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/checks"
)

// perf_error_logs reports logs in addon-domain docroots, which sit beside
// public_html, not under it. The truncate button must accept the same roots
// the check scans or the operator gets a finding they cannot act on.
func TestAPIPerfFixErrorLogAcceptsValidatedAddonDocroot(t *testing.T) {
	s := newTestServer(t, "tok")
	home := filepath.Join(realWebUITempDir(t), "home")
	main := filepath.Join(home, "alice", "public_html")
	addon := filepath.Join(home, "alice", "shop.example.com")
	for _, d := range []string{main, addon} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	mapPath := filepath.Join(t.TempDir(), "userdatadomains")
	row := "shop.example.com: alice==root==addon==example.com==" + addon + "==192.0.2.10:80==192.0.2.10:443====0==ea-php82\n"
	if err := os.WriteFile(mapPath, []byte(row), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(checks.SetUserdataDomainsPathForTest(mapPath))
	s.cfg.AccountRoots = []string{filepath.Join(home, "*", "public_html")}

	logPath := filepath.Join(addon, "error_log")
	if err := os.WriteFile(logPath, []byte("PHP Warning: noise\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	f := alert.Finding{
		Severity:  alert.Warning,
		Check:     "perf_error_logs",
		Message:   "Bloated error_log: " + logPath,
		Timestamp: time.Now(),
	}
	s.store.SetLatestFindings([]alert.Finding{f})
	body, err := json.Marshal(map[string]string{"path": logPath, "key": f.Key()})
	if err != nil {
		t.Fatal(err)
	}

	w := httptest.NewRecorder()
	s.apiPerfFixErrorLog(w, httptest.NewRequest("POST", "/", bytes.NewReader(body)))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
	info, err := os.Stat(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() != 0 {
		t.Fatalf("addon error_log size = %d, want 0", info.Size())
	}
}
