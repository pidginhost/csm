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
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422 with a per-item error", w.Code)
	}
	if !strings.Contains(w.Body.String(), "does not match") || !strings.Contains(w.Body.String(), `"succeeded":0`) {
		t.Fatalf("body = %q, want the item refused for path mismatch", w.Body.String())
	}
	if got := len(s.store.LatestFindings()); got != 1 {
		t.Fatalf("finding dismissed after a refused fix (left %d)", got)
	}
}

func TestFixTargetUsesStoredMessageWhenStoredPathIsEmpty(t *testing.T) {
	s := newTestServer(t, "tok")
	f := alert.Finding{
		Check:   "world_writable_php",
		Message: "World-writable PHP file: /home/alice/public_html/legacy.php",
		Details: "Mode: -rw-rw-rw-",
	}
	s.store.ClearLatestFindings()
	s.store.SetLatestFindings([]alert.Finding{f})

	message, details, path, dismissKey, err := s.fixTargetFromStore(
		f.Key(), f.Check, "changed client message", "changed details", "/tmp/substitute.php",
	)
	if err != nil {
		t.Fatalf("fixTargetFromStore: %v", err)
	}
	if message != f.Message || details != f.Details || path != "" {
		t.Fatalf("target = (%q, %q, %q), want stored message/details and empty path", message, details, path)
	}
	if dismissKey != f.Key() {
		t.Fatalf("dismiss key = %q, want %q", dismissKey, f.Key())
	}
}

func TestFixTargetKeyCannotBeBypassedWithChangedMessage(t *testing.T) {
	s := newTestServer(t, "tok")
	f := alert.Finding{
		Check:    "webshell",
		Message:  "Webshell found: /home/alice/public_html/evil.php",
		FilePath: "/home/alice/public_html/evil.php",
	}
	s.store.ClearLatestFindings()
	s.store.SetLatestFindings([]alert.Finding{f})

	_, _, _, _, err := s.fixTargetFromStore(
		f.Key(), f.Check, "different message", "", "/home/alice/public_html/other.php",
	)
	if err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("changed message bypassed stored path pin: %v", err)
	}
}

func TestFixTargetLegacyKeyStillPinsMatchingStoredFinding(t *testing.T) {
	s := newTestServer(t, "tok")
	f := alert.Finding{
		Check:    "webshell",
		Message:  "Webshell found: /home/alice/public_html/evil.php",
		Details:  "signature details make the canonical key differ",
		FilePath: "/home/alice/public_html/evil.php",
	}
	s.store.ClearLatestFindings()
	s.store.SetLatestFindings([]alert.Finding{f})

	legacyKey := f.Check + ":" + f.Message
	_, _, _, _, err := s.fixTargetFromStore(
		legacyKey, f.Check, f.Message, f.Details, "/home/alice/public_html/other.php",
	)
	if err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("legacy key bypassed the matching stored path: %v", err)
	}
}

func TestFixTargetWithoutKeyRefusesAmbiguousStoredFindings(t *testing.T) {
	s := newTestServer(t, "tok")
	findings := []alert.Finding{
		{Check: "webshell", Message: "Webshell found", Details: "first", FilePath: "/home/alice/public_html/one.php"},
		{Check: "webshell", Message: "Webshell found", Details: "second", FilePath: "/home/alice/public_html/two.php"},
	}
	s.store.ClearLatestFindings()
	s.store.SetLatestFindings(findings)

	_, _, _, _, err := s.fixTargetFromStore("", "webshell", "Webshell found", "", findings[0].FilePath)
	if err == nil || !strings.Contains(err.Error(), "key is required") {
		t.Fatalf("ambiguous keyless fix was not refused: %v", err)
	}
}
