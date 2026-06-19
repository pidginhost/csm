package webui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
)

// TestApiVerifyFindingResolvedDismisses: a re-check that finds the condition
// gone (here, a quarantine-family file that no longer exists) clears the
// finding from the latest set.
func TestApiVerifyFindingResolvedDismisses(t *testing.T) {
	s := newTestServer(t, "tok")
	f := alert.Finding{
		Check:   "webshell",
		Message: "Known webshell found: /home/no-such-user-xyz/public_html/gone.php",
	}
	s.store.ClearLatestFindings()
	s.store.SetLatestFindings([]alert.Finding{f})

	w := httptest.NewRecorder()
	body := `{"check":"webshell","message":"Known webshell found: /home/no-such-user-xyz/public_html/gone.php","file_path":"/home/no-such-user-xyz/public_html/gone.php"}`
	req := httptest.NewRequest("POST", "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	s.apiVerifyFinding(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	var res struct {
		Checked  bool `json:"checked"`
		Resolved bool `json:"resolved"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &res); err != nil {
		t.Fatalf("bad JSON: %v", err)
	}
	if !res.Checked || !res.Resolved {
		t.Fatalf("expected checked+resolved, got %+v (body %s)", res, w.Body.String())
	}
	if got := len(s.store.LatestFindings()); got != 0 {
		t.Errorf("resolved finding should be dismissed, still have %d", got)
	}
}

// TestApiVerifyFindingNotResolvedKeeps: a check type with no automated
// re-check returns checked=false and must NOT dismiss the finding.
func TestApiVerifyFindingNotResolvedKeeps(t *testing.T) {
	s := newTestServer(t, "tok")
	f := alert.Finding{Check: "brute_force", Message: "SSH brute force from 198.51.100.7"}
	s.store.ClearLatestFindings()
	s.store.SetLatestFindings([]alert.Finding{f})

	w := httptest.NewRecorder()
	body := `{"check":"brute_force","message":"SSH brute force from 198.51.100.7"}`
	req := httptest.NewRequest("POST", "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	s.apiVerifyFinding(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	var res struct {
		Checked  bool `json:"checked"`
		Resolved bool `json:"resolved"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &res); err != nil {
		t.Fatalf("bad JSON: %v", err)
	}
	if res.Checked || res.Resolved {
		t.Errorf("unknown type should be unchecked+unresolved, got %+v", res)
	}
	if got := len(s.store.LatestFindings()); got != 1 {
		t.Errorf("unresolved finding must remain, have %d want 1", got)
	}
}

func TestApiVerifyFindingMissingFields(t *testing.T) {
	s := newTestServer(t, "tok")
	for _, body := range []string{`{}`, `{"check":"webshell"}`, `{"message":"x"}`} {
		w := httptest.NewRecorder()
		req := httptest.NewRequest("POST", "/", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		s.apiVerifyFinding(w, req)
		if w.Code != http.StatusBadRequest {
			t.Errorf("body %s: status = %d, want 400", body, w.Code)
		}
	}
}

func TestApiVerifyFindingRejectsGET(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	s.apiVerifyFinding(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", w.Code)
	}
}
