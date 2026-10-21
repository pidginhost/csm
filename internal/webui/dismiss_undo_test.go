package webui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/state"
)

func TestBulkDismissRecordsOneUndoForEveryKey(t *testing.T) {
	s := newTestServerWithBbolt(t, "tok")
	a := alert.Finding{Check: "webshell", Severity: alert.Critical, Message: "Webshell A"}
	b := alert.Finding{Check: "webshell", Severity: alert.High, Message: "Webshell B"}
	s.store.Update([]alert.Finding{a, b})
	s.store.SetLatestFindings([]alert.Finding{a, b})

	// Duplicate keys are one dismissal, so their undo cannot invalidate itself.
	body, _ := json.Marshal(map[string][]string{"keys": {a.Key(), b.Key(), a.Key()}})
	rec := httptest.NewRecorder()
	s.apiDismissFinding(rec, bearerRequest("POST", "/api/v1/dismiss", body))
	if rec.Code != http.StatusOK {
		t.Fatalf("dismiss status=%d body=%s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Count     int    `json:"count"`
		UndoToken string `json:"undo_token"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Count != 2 || resp.UndoToken == "" {
		t.Fatalf("bulk dismiss response = %s", rec.Body.String())
	}
	if n := len(s.store.LatestFindings()); n != 0 {
		t.Fatalf("%d findings still listed", n)
	}

	runBody, _ := json.Marshal(undoRunRequest{ID: resp.UndoToken})
	rec = httptest.NewRecorder()
	s.apiUndoRun(rec, bearerRequest("POST", "/api/v1/undo/run", runBody))
	if rec.Code != http.StatusOK {
		t.Fatalf("undo status=%d body=%s", rec.Code, rec.Body.String())
	}
	if n := len(s.store.LatestFindings()); n != 2 {
		t.Fatalf("undo restored %d findings, want 2", n)
	}
}

func TestDismissRejectsAmbiguousOrOversizedRequests(t *testing.T) {
	s := newTestServerWithBbolt(t, "tok")
	tooMany := make([]string, dismissBulkMax+1)
	for i := range tooMany {
		tooMany[i] = "webshell:x"
	}
	for name, body := range map[string]interface{}{
		"both":     map[string]interface{}{"key": "webshell:a", "keys": []string{"webshell:b"}},
		"neither":  map[string]interface{}{},
		"too many": map[string]interface{}{"keys": tooMany},
		"blank":    map[string]interface{}{"keys": []string{""}},
	} {
		raw, _ := json.Marshal(body)
		rec := httptest.NewRecorder()
		s.apiDismissFinding(rec, bearerRequest("POST", "/api/v1/dismiss", raw))
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: status=%d, want 400", name, rec.Code)
		}
	}
}

func TestDismissOffersUndoThatRestoresTheFinding(t *testing.T) {
	s := newTestServerWithBbolt(t, "tok")
	f := alert.Finding{Check: "webshell", Severity: alert.Critical, Message: "Webshell found", FilePath: "/home/a/public_html/x.php"}
	s.store.Update([]alert.Finding{f})
	s.store.SetLatestFindings([]alert.Finding{f})

	body, _ := json.Marshal(map[string]string{"key": f.Key()})
	rec := httptest.NewRecorder()
	s.apiDismissFinding(rec, bearerRequest("POST", "/api/v1/dismiss", body))
	if rec.Code != http.StatusOK {
		t.Fatalf("dismiss status=%d body=%s", rec.Code, rec.Body.String())
	}
	var resp struct {
		UndoToken string `json:"undo_token"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.UndoToken == "" {
		t.Fatalf("dismiss must offer an undo token: %s", rec.Body.String())
	}
	if n := len(s.store.LatestFindings()); n != 0 {
		t.Fatalf("finding still listed after dismiss: %d", n)
	}

	runBody, _ := json.Marshal(undoRunRequest{ID: resp.UndoToken})
	rec = httptest.NewRecorder()
	s.apiUndoRun(rec, bearerRequest("POST", "/api/v1/undo/run", runBody))
	if rec.Code != http.StatusOK {
		t.Fatalf("undo status=%d body=%s", rec.Code, rec.Body.String())
	}
	var run undoRunResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &run); err != nil {
		t.Fatal(err)
	}
	if run.Count != 1 {
		t.Fatalf("undo count = %d, want 1", run.Count)
	}
	latest := s.store.LatestFindings()
	if len(latest) != 1 || latest[0].Key() != f.Key() {
		t.Fatalf("undo must list the finding again, got %+v", latest)
	}
	if e, _ := s.store.EntryForKey(f.Key()); e.IsBaseline {
		t.Fatal("undo must re-arm alerts for the finding")
	}

	found := false
	for _, e := range readUIAuditLog(s.cfg.StatePath, 20) {
		if e.Action == "undo_dismiss" {
			found = true
		}
	}
	if !found {
		t.Fatal("undo of a dismissal must be audited")
	}
}

// An undo that waited for the next due flush could be lost to a hard kill
// after the dismissal had already reached disk. The restarted daemon would
// then suppress a finding the UI lists as active.
func TestUndoDismissSavesStateAtOnce(t *testing.T) {
	s := newTestServerWithBbolt(t, "tok")
	dir := t.TempDir()
	st, err := state.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	s.store = st

	f := alert.Finding{Check: "webshell", Severity: alert.Critical, Message: "Webshell found", FilePath: "/home/a/public_html/x.php"}
	s.store.Update([]alert.Finding{f})
	s.store.SetLatestFindings([]alert.Finding{f})

	body, _ := json.Marshal(map[string]string{"key": f.Key()})
	rec := httptest.NewRecorder()
	s.apiDismissFinding(rec, bearerRequest("POST", "/api/v1/dismiss", body))
	if rec.Code != http.StatusOK {
		t.Fatalf("dismiss status=%d body=%s", rec.Code, rec.Body.String())
	}
	var resp struct {
		UndoToken string `json:"undo_token"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	// A due flush puts the dismissal on disk.
	if err := s.store.Flush(); err != nil {
		t.Fatal(err)
	}
	if !savedEntry(t, dir, f.Key()).IsBaseline {
		t.Fatal("precondition: the dismissal should be on disk")
	}

	runBody, _ := json.Marshal(undoRunRequest{ID: resp.UndoToken})
	rec = httptest.NewRecorder()
	s.apiUndoRun(rec, bearerRequest("POST", "/api/v1/undo/run", runBody))
	if rec.Code != http.StatusOK {
		t.Fatalf("undo status=%d body=%s", rec.Code, rec.Body.String())
	}
	if savedEntry(t, dir, f.Key()).IsBaseline {
		t.Fatal("undo did not reach state.json: a restart would suppress the finding")
	}
}

func savedEntry(t *testing.T, dir, key string) state.Entry {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	var entries map[string]state.Entry
	if err := json.Unmarshal(data, &entries); err != nil {
		t.Fatal(err)
	}
	e, ok := entries[key]
	if !ok {
		t.Fatalf("state.json has no entry for %s", key)
	}
	return e
}
