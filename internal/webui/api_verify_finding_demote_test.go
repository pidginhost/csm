package webui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/checks"
)

// The unattended sweep demotes a finding whose flagged content is gone but whose
// file changed since detection. The operator's Re-check ran the same verifier,
// reached the same verdict, and then discarded it: the response said "not
// resolved" and the finding kept its original severity. Someone who cleaned a
// file by hand and pressed Re-check saw nothing happen, and could not tell that
// apart from a re-check that had failed.

// withVerdict makes one server see a fixed verifier verdict, so these tests
// exercise what the handler does with one rather than re-deriving it from a
// file the webui package cannot place under a real account root. Keeping the
// seam on the server avoids changing verifier behavior for concurrent servers.
func withVerdict(t *testing.T, s *Server, res checks.VerifyResult) {
	t.Helper()
	s.verifyFinding = func(checks.VerifyInput) checks.VerifyResult { return res }
}

func storedFinding(t *testing.T, s *Server, key string) alert.Finding {
	t.Helper()
	for _, f := range s.store.LatestFindings() {
		if f.Key() == key {
			return f
		}
	}
	t.Fatalf("finding %q is no longer stored", key)
	return alert.Finding{}
}

func TestApiVerifyFindingDemoteLowersSeverity(t *testing.T) {
	s := newTestServer(t, "tok")
	path := "/home/alice/public_html/index.php"
	f := alert.Finding{
		Check:    "yara_match_scheduled",
		Message:  "YARA rule match [obfuscation_fragmented_base64_eval]: " + path,
		FilePath: path,
		Severity: alert.Critical,
	}
	s.store.ClearLatestFindings()
	s.store.SetLatestFindings([]alert.Finding{f})
	withVerdict(t, s, checks.VerifyResult{
		Checked: true, Demote: true,
		Detail: "replacement is an inert PHP stub -- confirm remediation",
	})

	w := httptest.NewRecorder()
	body := `{"check":"yara_match_scheduled","message":"` + f.Message + `","file_path":"` + path + `"}`
	req := httptest.NewRequest("POST", "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	s.apiVerifyFinding(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	var res checks.VerifyResult
	if err := json.Unmarshal(w.Body.Bytes(), &res); err != nil {
		t.Fatalf("bad JSON: %v", err)
	}
	if !res.Demote {
		t.Fatalf("response should carry the demotion verdict, got %+v", res)
	}
	var response verifyFindingResponse
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatalf("bad response JSON: %v", err)
	}
	if response.SeverityChange != "demoted" {
		t.Fatalf("severity_change = %q, want demoted", response.SeverityChange)
	}
	if got := len(s.store.LatestFindings()); got != 1 {
		t.Fatalf("a demoted finding is never cleared, have %d want 1", got)
	}
	got := storedFinding(t, s, f.Key())
	if got.Severity != alert.Warning {
		t.Errorf("severity = %v, want Warning", got.Severity)
	}
	if got.DemotedFrom != alert.Critical {
		t.Errorf("DemotedFrom = %v, want Critical so the demotion can be reversed", got.DemotedFrom)
	}
}

func TestApiVerifyFindingRestoresSeverityWhenNoLongerInert(t *testing.T) {
	s := newTestServer(t, "tok")
	path := "/home/alice/public_html/index.php"
	f := alert.Finding{
		Check:       "yara_match_scheduled",
		Message:     "YARA rule match [obfuscation_fragmented_base64_eval]: " + path,
		FilePath:    path,
		Severity:    alert.Warning,
		DemotedFrom: alert.Critical,
	}
	s.store.ClearLatestFindings()
	s.store.SetLatestFindings([]alert.Finding{f})
	withVerdict(t, s, checks.VerifyResult{Checked: true, Demote: false, Detail: "still flagged"})

	w := httptest.NewRecorder()
	body := `{"check":"yara_match_scheduled","message":"` + f.Message + `","file_path":"` + path + `"}`
	req := httptest.NewRequest("POST", "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	s.apiVerifyFinding(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	got := storedFinding(t, s, f.Key())
	if got.Severity != alert.Critical {
		t.Errorf("severity = %v, want Critical restored", got.Severity)
	}
	var response verifyFindingResponse
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatalf("bad response JSON: %v", err)
	}
	if response.SeverityChange != "restored" {
		t.Fatalf("severity_change = %q, want restored", response.SeverityChange)
	}
}

func TestApiVerifyFindingResolvedDemotionStillDismissesFirst(t *testing.T) {
	s := newTestServer(t, "tok")
	path := "/home/alice/public_html/index.php"
	f := alert.Finding{
		Check:       "yara_match_scheduled",
		Message:     "YARA rule match [obfuscation_fragmented_base64_eval]: " + path,
		FilePath:    path,
		Severity:    alert.Warning,
		DemotedFrom: alert.Critical,
	}
	s.store.ClearLatestFindings()
	s.store.SetLatestFindings([]alert.Finding{f})
	withVerdict(t, s, checks.VerifyResult{Checked: true, Resolved: true, Detail: "file no longer present"})

	w := httptest.NewRecorder()
	body := `{"check":"yara_match_scheduled","message":"` + f.Message + `","file_path":"` + path + `"}`
	req := httptest.NewRequest("POST", "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	s.apiVerifyFinding(w, req)

	if got := len(s.store.LatestFindings()); got != 0 {
		t.Fatalf("a resolved finding is still cleared outright, have %d want 0", got)
	}
}

func TestApiVerifyFindingUncheckedLeavesSeverityAlone(t *testing.T) {
	s := newTestServer(t, "tok")
	path := "/home/alice/public_html/index.php"
	f := alert.Finding{
		Check:    "yara_match_scheduled",
		Message:  "YARA rule match [obfuscation_fragmented_base64_eval]: " + path,
		FilePath: path,
		Severity: alert.Critical,
	}
	s.store.ClearLatestFindings()
	s.store.SetLatestFindings([]alert.Finding{f})
	withVerdict(t, s, checks.VerifyResult{Checked: false, Detail: "YARA scanner unavailable"})

	w := httptest.NewRecorder()
	body := `{"check":"yara_match_scheduled","message":"` + f.Message + `","file_path":"` + path + `"}`
	req := httptest.NewRequest("POST", "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	s.apiVerifyFinding(w, req)

	got := storedFinding(t, s, f.Key())
	if got.Severity != alert.Critical {
		t.Errorf("an inconclusive re-check must not change severity, got %v", got.Severity)
	}
}

func TestApiVerifyFindingUncheckedRestoresAutomaticDemotion(t *testing.T) {
	s := newTestServer(t, "tok")
	f := alert.Finding{
		Check: "yara_match_scheduled", Message: "flagged index.php", FilePath: "/home/alice/public_html/index.php",
		Severity: alert.Warning, DemotedFrom: alert.Critical,
	}
	s.store.ClearLatestFindings()
	s.store.SetLatestFindings([]alert.Finding{f})
	withVerdict(t, s, checks.VerifyResult{Checked: false, Detail: "YARA scanner unavailable"})

	w := httptest.NewRecorder()
	body := `{"check":"yara_match_scheduled","message":"flagged index.php"}`
	req := httptest.NewRequest("POST", "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	s.apiVerifyFinding(w, req)

	got := storedFinding(t, s, f.Key())
	if got.Severity != alert.Critical {
		t.Fatalf("an inconclusive re-check must restore the fail-safe severity, got %v", got.Severity)
	}
	var response verifyFindingResponse
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatalf("bad response JSON: %v", err)
	}
	if response.SeverityChange != "restored" {
		t.Fatalf("severity_change = %q, want restored", response.SeverityChange)
	}
}

func TestApiVerifyFindingDoesNotReportRejectedDemotion(t *testing.T) {
	s := newTestServer(t, "tok")
	f := alert.Finding{
		Check: "yara_match_scheduled", Message: "flagged index.php", FilePath: "/home/alice/public_html/index.php",
		Severity: alert.Critical,
	}
	s.store.ClearLatestFindings()
	s.store.SetLatestFindings([]alert.Finding{f})
	// Simulate a scan refreshing the finding after the handler took its
	// snapshot but before it tries to apply the verdict.
	s.verifyFinding = func(checks.VerifyInput) checks.VerifyResult {
		refreshed := f
		refreshed.ContentSHA256 = "newer-scan-snapshot"
		s.store.SetLatestFindings([]alert.Finding{refreshed})
		return checks.VerifyResult{Checked: true, Demote: true, Detail: "inert replacement"}
	}

	w := httptest.NewRecorder()
	body := `{"check":"yara_match_scheduled","message":"flagged index.php"}`
	req := httptest.NewRequest("POST", "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	s.apiVerifyFinding(w, req)

	got := storedFinding(t, s, f.Key())
	if got.Severity != alert.Critical || got.ContentSHA256 != "newer-scan-snapshot" {
		t.Fatalf("stale verdict overwrote the refreshed finding: %+v", got)
	}
	var response verifyFindingResponse
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatalf("bad response JSON: %v", err)
	}
	if !response.Demote || response.SeverityChange != "" {
		t.Fatalf("response must separate verdict from rejected mutation: %+v", response)
	}
}

func TestApiVerifyFindingClientFieldsCannotSelectSeverityTarget(t *testing.T) {
	s := newTestServer(t, "tok")
	victim := alert.Finding{
		Check: "yara_match_scheduled", Message: "stored finding", FilePath: "/home/alice/public_html/index.php",
		Severity: alert.Critical,
	}
	s.store.ClearLatestFindings()
	s.store.SetLatestFindings([]alert.Finding{victim})
	withVerdict(t, s, checks.VerifyResult{Checked: true, Demote: true, Detail: "inert replacement"})

	w := httptest.NewRecorder()
	body := `{"key":"` + victim.Key() + `","check":"yara_match_scheduled","message":"client-supplied finding","file_path":"/tmp/other.php"}`
	req := httptest.NewRequest("POST", "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	s.apiVerifyFinding(w, req)

	if got := storedFinding(t, s, victim.Key()); got.Severity != alert.Critical {
		t.Fatalf("client fields selected a stored finding for mutation: %+v", got)
	}
	var response verifyFindingResponse
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatalf("bad response JSON: %v", err)
	}
	if response.SeverityChange != "" {
		t.Fatalf("unmatched client input reported an applied severity change: %+v", response)
	}
}
