package webui

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
)

// A fix acts on the file the stored finding names. The client may repeat
// that path but must not be able to substitute another one: a request that
// names /home/alice against a webshell finding would otherwise hand the
// account's home directory to the quarantine step.
func TestAPIFixRefusesPathDifferingFromStoredFinding(t *testing.T) {
	s := newTestServer(t, "tok")
	f := alert.Finding{
		Check:    "webshell",
		Message:  "Webshell found: /home/alice/public_html/evil.php",
		Details:  "score 9",
		FilePath: "/home/alice/public_html/evil.php",
	}
	s.store.ClearLatestFindings()
	s.store.SetLatestFindings([]alert.Finding{f})

	body := `{"check":"webshell","message":"Webshell found: /home/alice/public_html/evil.php","details":"score 9","file_path":"/home/alice","key":"` + f.Key() + `"}`
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	s.apiFix(w, req)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "does not match") {
		t.Fatalf("status = %d body = %q, want 400 path mismatch", w.Code, w.Body.String())
	}
	if got := len(s.store.LatestFindings()); got != 1 {
		t.Fatalf("finding dismissed after a refused fix (left %d)", got)
	}
}

func TestAPIBulkFixRefusesPathDifferingFromStoredFinding(t *testing.T) {
	s := newTestServer(t, "tok")
	f := alert.Finding{
		Check:    "webshell",
		Message:  "Webshell found: /home/alice/public_html/evil.php",
		FilePath: "/home/alice/public_html/evil.php",
	}
	s.store.ClearLatestFindings()
	s.store.SetLatestFindings([]alert.Finding{f})

	body := `[{"check":"webshell","message":"Webshell found: /home/alice/public_html/evil.php","file_path":"/tmp","key":"` + f.Key() + `"}]`
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	s.apiBulkFix(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 with a per-item error", w.Code)
	}
	if !strings.Contains(w.Body.String(), "does not match") || !strings.Contains(w.Body.String(), `"succeeded": 0`) {
		t.Fatalf("body = %q, want the item refused for path mismatch", w.Body.String())
	}
	if got := len(s.store.LatestFindings()); got != 1 {
		t.Fatalf("finding dismissed after a refused fix (left %d)", got)
	}
}
