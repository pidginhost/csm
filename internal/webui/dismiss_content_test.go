package webui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
)

var (
	dismissShaA = strings.Repeat("a", 64)
	dismissShaB = strings.Repeat("b", 64)
)

func listedYARAFinding(s *Server, path, sha string) alert.Finding {
	f := alert.Finding{Check: "yara_match_scheduled", Severity: alert.Critical,
		Message:  "YARA rule match [webshell_generic]: " + path,
		FilePath: path, ContentSHA256: sha}
	s.store.Update([]alert.Finding{f})
	s.store.SetLatestFindings([]alert.Finding{f})
	return f
}

func postDismiss(t *testing.T, s *Server, body any) *httptest.ResponseRecorder {
	t.Helper()
	raw, _ := json.Marshal(body)
	rec := httptest.NewRecorder()
	s.apiDismissFinding(rec, bearerRequest("POST", "/api/v1/dismiss", raw))
	return rec
}

func pendingUndoID(t *testing.T, s *Server) string {
	t.Helper()
	rec := httptest.NewRecorder()
	s.apiUndoPending(rec, bearerRequest("GET", "/api/v1/undo/pending", nil))
	var entry undoPendingView
	_ = json.Unmarshal(rec.Body.Bytes(), &entry)
	return entry.ID
}

func TestDismissRefusesRowChangedSincePageLoad(t *testing.T) {
	s := newTestServerWithBbolt(t, "tok")
	f := listedYARAFinding(s, "/home/a/public_html/x.php", dismissShaB)
	key := f.Key()

	rec := postDismiss(t, s, map[string]any{"key": key, "contents": map[string]string{key: dismissShaA}})

	if rec.Code != http.StatusConflict {
		t.Fatalf("status=%d body=%s, want 409", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "changed since the page loaded") {
		t.Fatalf("refusal body = %s", rec.Body.String())
	}
	if e, _ := s.store.EntryForKey(key); e.IsBaseline {
		t.Fatal("refused dismissal marked the finding dismissed")
	}
	if n := len(s.store.LatestFindings()); n != 1 {
		t.Fatalf("refused dismissal changed the list: %d rows", n)
	}
	if id := pendingUndoID(t, s); id != "" {
		t.Fatalf("refused dismissal recorded undo %q", id)
	}
}

func TestBulkDismissRefusesOnlyChangedRows(t *testing.T) {
	s := newTestServerWithBbolt(t, "tok")
	x := listedYARAFinding(s, "/home/a/public_html/x.php", dismissShaA)
	y := listedYARAFinding(s, "/home/a/public_html/y.php", dismissShaB)

	rec := postDismiss(t, s, map[string]any{
		"keys":     []string{x.Key(), y.Key()},
		"contents": map[string]string{x.Key(): dismissShaA, y.Key(): dismissShaA},
	})

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Count     int      `json:"count"`
		Refused   []string `json:"refused"`
		UndoToken string   `json:"undo_token"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Count != 1 || len(resp.Refused) != 1 || resp.Refused[0] != y.Key() || resp.UndoToken == "" {
		t.Fatalf("bulk response = %s", rec.Body.String())
	}
	if e, _ := s.store.EntryForKey(x.Key()); !e.IsBaseline || e.ContentSHA256 != dismissShaA {
		t.Fatalf("unchanged row not dismissed: %+v", e)
	}
	if e, _ := s.store.EntryForKey(y.Key()); e.IsBaseline {
		t.Fatal("changed row dismissed")
	}

	runBody, _ := json.Marshal(undoRunRequest{ID: resp.UndoToken})
	rec = httptest.NewRecorder()
	s.apiUndoRun(rec, bearerRequest("POST", "/api/v1/undo/run", runBody))
	if rec.Code != http.StatusOK {
		t.Fatalf("undo status=%d body=%s", rec.Code, rec.Body.String())
	}
	if e, _ := s.store.EntryForKey(x.Key()); e.IsBaseline {
		t.Fatal("undo left the applied dismissal in place")
	}
	if n := len(s.store.LatestFindings()); n != 2 {
		t.Fatalf("after undo %d rows listed, want 2", n)
	}
}

func TestDismissWithoutContentsRecordsListedHash(t *testing.T) {
	s := newTestServerWithBbolt(t, "tok")
	f := listedYARAFinding(s, "/home/a/public_html/x.php", dismissShaA)

	rec := postDismiss(t, s, map[string]any{"key": f.Key()})

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if e, _ := s.store.EntryForKey(f.Key()); !e.IsBaseline || e.ContentSHA256 != dismissShaA {
		t.Fatalf("entry = %+v; want the listed content recorded", e)
	}
}
