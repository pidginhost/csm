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
	s.store.Update([]alert.Finding{f})
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
	if len(s.store.LatestFindings()) != 0 {
		t.Fatal("fixed performance finding still listed")
	}
	if len(s.store.FilterNew([]alert.Finding{f})) != 1 {
		t.Fatal("fixed performance finding was permanently acknowledged")
	}
	info, err := os.Stat(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() != 0 {
		t.Fatalf("addon error_log size = %d, want 0", info.Size())
	}
}

func TestPerfFixCannotResolveAnotherTarget(t *testing.T) {
	for _, check := range []string{"perf_error_logs", "perf_wp_config"} {
		t.Run(check, func(t *testing.T) {
			s := newTestServer(t, "tok")
			root := realWebUITempDir(t)
			s.cfg.AccountRoots = []string{root}
			name, content := "error_log", "PHP Warning: noise\n"
			if check == "perf_wp_config" {
				name, content = ".user.ini", "display_errors = On\n"
			}
			fixedPath := filepath.Join(root, name)
			if err := os.WriteFile(fixedPath, []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			otherPath := filepath.Join(root, "other", name)
			f := alert.Finding{Check: check, Message: "Bloated error_log: " + otherPath, Severity: alert.Warning}
			if check == "perf_wp_config" {
				f.Message = "display_errors enabled in production for alice"
				f.Details = "File: " + otherPath + ", Value: On"
			}
			s.store.Update([]alert.Finding{f})
			s.store.SetLatestFindings([]alert.Finding{f})
			body, err := json.Marshal(map[string]string{"path": fixedPath, "key": f.Key()})
			if err != nil {
				t.Fatal(err)
			}
			w := httptest.NewRecorder()
			r := httptest.NewRequest("POST", "/", bytes.NewReader(body))
			if check == "perf_error_logs" {
				s.apiPerfFixErrorLog(w, r)
			} else {
				s.apiPerfFixDisplayErrors(w, r)
			}
			if w.Code != http.StatusOK {
				t.Fatalf("status=%d: %s", w.Code, w.Body.String())
			}
			if got := s.store.LatestFindings(); len(got) != 1 || got[0].Key() != f.Key() {
				t.Fatalf("fix cleared another target: %+v", got)
			}
			if _, ok := s.store.EntryForKey(f.Key()); !ok {
				t.Fatal("fix cleared another target's alert state")
			}
		})
	}
}

func TestWPCronResolutionRequiresCompleteTarget(t *testing.T) {
	path := "/home/alice/public_html/wp-config.php"
	for _, target := range []string{path, path + " - other/wp-config.php"} {
		t.Run(target, func(t *testing.T) {
			s := newTestServer(t, "tok")
			f := alert.Finding{
				Check: "perf_wp_cron", Message: "WP-Cron not disabled for alice",
				Details: "File: " + target + " - add define('DISABLE_WP_CRON', true); and use a real cron job instead",
			}
			s.store.Update([]alert.Finding{f})
			s.store.SetLatestFindings([]alert.Finding{f})
			resolved := s.preparePerfResolution(f.Key(), f.Check, path)()
			if resolved != (target == path) {
				t.Fatalf("resolved=%v for target %q", resolved, target)
			}
			if got := len(s.store.FilterNew([]alert.Finding{f})); (got == 1) != resolved {
				t.Fatalf("new count=%d, resolved=%v", got, resolved)
			}
		})
	}
}
