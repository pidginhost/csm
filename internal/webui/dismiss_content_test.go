package webui

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
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
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	s.apiDismissFinding(rec, bearerRequest("POST", "/api/v1/dismiss", raw))
	return rec
}

func pendingUndoID(t *testing.T, s *Server) string {
	t.Helper()
	rec := httptest.NewRecorder()
	s.apiUndoPending(rec, bearerRequest("GET", "/api/v1/undo/pending", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("pending undo status=%d body=%s", rec.Code, rec.Body.String())
	}
	var entry undoPendingView
	if err := json.Unmarshal(rec.Body.Bytes(), &entry); err != nil {
		t.Fatal(err)
	}
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
	if audit := readUIAuditLog(s.cfg.StatePath, 20); len(audit) != 0 {
		t.Fatalf("refused dismissal was audited: %+v", audit)
	}
}

func TestBulkDismissRefusesOnlyChangedRows(t *testing.T) {
	s := newTestServerWithBbolt(t, "tok")
	x := listedYARAFinding(s, "/home/a/public_html/x.php", dismissShaA)
	y := listedYARAFinding(s, "/home/a/public_html/y.php", dismissShaB)
	yBefore, _ := s.store.EntryForKey(y.Key())

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
	audit := readUIAuditLog(s.cfg.StatePath, 20)
	if len(audit) != 1 || audit[0].Action != "dismiss" || audit[0].Target != x.Key() {
		t.Fatalf("audit must contain only the applied dismissal: %+v", audit)
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
		t.Fatalf("undo count=%d, want only the applied dismissal", run.Count)
	}
	if e, _ := s.store.EntryForKey(x.Key()); e.IsBaseline {
		t.Fatal("undo left the applied dismissal in place")
	}
	if n := len(s.store.LatestFindings()); n != 2 {
		t.Fatalf("after undo %d rows listed, want 2", n)
	}
	if e, ok := s.store.EntryForKey(y.Key()); !ok || e != yBefore {
		t.Fatalf("undo changed the refused finding: %+v", e)
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

func TestDismissContentsCannotAddTargets(t *testing.T) {
	for _, bulk := range []bool{false, true} {
		for _, claimed := range []bool{false, true} {
			t.Run(fmt.Sprintf("bulk=%t/claimed=%t", bulk, claimed), func(t *testing.T) {
				s := newTestServerWithBbolt(t, "tok")
				x := listedYARAFinding(s, "/home/a/public_html/x.php", dismissShaA)
				y := listedYARAFinding(s, "/home/a/public_html/y.php", dismissShaB)
				yBefore, _ := s.store.EntryForKey(y.Key())
				contents := map[string]string{y.Key(): dismissShaB}
				if claimed {
					contents[x.Key()] = dismissShaA
				}
				body := map[string]any{"contents": contents}
				if bulk {
					body["keys"] = []string{x.Key(), x.Key()}
				} else {
					body["key"] = x.Key()
				}
				rec := postDismiss(t, s, body)
				if rec.Code != http.StatusOK {
					t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
				}
				var resp struct {
					Count int `json:"count"`
				}
				if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
					t.Fatal(err)
				}
				if resp.Count != 1 {
					t.Fatalf("count=%d, want 1", resp.Count)
				}
				if e, _ := s.store.EntryForKey(x.Key()); !e.IsBaseline || e.ContentSHA256 != dismissShaA {
					t.Fatalf("requested finding was not dismissed: %+v", e)
				}
				if e, ok := s.store.EntryForKey(y.Key()); !ok || e != yBefore {
					t.Fatalf("unrequested finding changed: %+v", e)
				}
				if latest := s.store.LatestFindings(); len(latest) != 1 || latest[0].Key() != y.Key() {
					t.Fatalf("unrequested finding must remain listed: %+v", latest)
				}
				audit := readUIAuditLog(s.cfg.StatePath, 20)
				if len(audit) != 1 || audit[0].Action != "dismiss" || audit[0].Target != x.Key() {
					t.Fatalf("audit must contain only the requested dismissal: %+v", audit)
				}
			})
		}
	}
}

func TestBulkDismissAllChangedPreservesPendingUndo(t *testing.T) {
	s := newTestServerWithBbolt(t, "tok")
	z := listedYARAFinding(s, "/home/a/public_html/z.php", dismissShaA)
	if rec := postDismiss(t, s, map[string]any{"key": z.Key()}); rec.Code != http.StatusOK {
		t.Fatalf("initial dismissal status=%d body=%s", rec.Code, rec.Body.String())
	}
	pending := pendingUndoID(t, s)
	if pending == "" {
		t.Fatal("initial dismissal has no undo")
	}
	x := listedYARAFinding(s, "/home/a/public_html/x.php", dismissShaB)
	y := listedYARAFinding(s, "/home/a/public_html/y.php", dismissShaB)
	xBefore, _ := s.store.EntryForKey(x.Key())
	yBefore, _ := s.store.EntryForKey(y.Key())
	latest := s.store.LatestFindings()
	rec := postDismiss(t, s, map[string]any{
		"keys":     []string{x.Key(), y.Key(), x.Key()},
		"contents": map[string]string{x.Key(): dismissShaA, y.Key(): ""},
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
	if resp.Count != 0 || !reflect.DeepEqual(resp.Refused, []string{x.Key(), y.Key()}) || resp.UndoToken != "" {
		t.Fatalf("all-refused response = %s", rec.Body.String())
	}
	if id := pendingUndoID(t, s); id != pending {
		t.Fatalf("pending undo=%q, want original %q", id, pending)
	}
	if got := s.store.LatestFindings(); !reflect.DeepEqual(got, latest) {
		t.Fatalf("refused dismissals changed the list: %+v", got)
	}
	if e, ok := s.store.EntryForKey(x.Key()); !ok || e != xBefore {
		t.Fatalf("refused dismissal changed %q: %+v", x.Key(), e)
	}
	if e, ok := s.store.EntryForKey(y.Key()); !ok || e != yBefore {
		t.Fatalf("refused dismissal changed %q: %+v", y.Key(), e)
	}
	audit := readUIAuditLog(s.cfg.StatePath, 20)
	if len(audit) != 1 || audit[0].Action != "dismiss" || audit[0].Target != z.Key() {
		t.Fatalf("refused dismissals changed the audit log: %+v", audit)
	}
}

func TestDismissRejectsMalformedContentHash(t *testing.T) {
	for name, shown := range map[string]any{
		"not hex":   "not-a-content-hash",
		"uppercase": strings.Repeat("A", 64),
		"too short": strings.Repeat("a", 63),
		"too long":  strings.Repeat("a", 4096),
		"null":      nil,
		"boolean":   false,
		"number":    0,
		"object":    map[string]any{},
		"array":     []string{},
	} {
		t.Run(name, func(t *testing.T) {
			for _, bulk := range []bool{false, true} {
				t.Run(fmt.Sprintf("bulk=%t", bulk), func(t *testing.T) {
					s := newTestServerWithBbolt(t, "tok")
					x := listedYARAFinding(s, "/home/a/public_html/x.php", dismissShaA)
					y := listedYARAFinding(s, "/home/a/public_html/y.php", "")
					xBefore, _ := s.store.EntryForKey(x.Key())
					yBefore, _ := s.store.EntryForKey(y.Key())
					latest := s.store.LatestFindings()
					body := map[string]any{"key": y.Key(), "contents": map[string]any{y.Key(): shown}}
					if bulk {
						body = map[string]any{
							"keys":     []string{x.Key(), y.Key()},
							"contents": map[string]any{x.Key(): dismissShaA, y.Key(): shown},
						}
					}

					rec := postDismiss(t, s, body)

					if rec.Code != http.StatusBadRequest {
						t.Errorf("status=%d body=%s, want 400", rec.Code, rec.Body.String())
					}
					if e, _ := s.store.EntryForKey(x.Key()); e != xBefore {
						t.Errorf("malformed request changed the valid entry: %+v", e)
					}
					if e, _ := s.store.EntryForKey(y.Key()); e != yBefore {
						t.Errorf("malformed hash changed the entry: %+v", e)
					}
					if got := s.store.LatestFindings(); !reflect.DeepEqual(got, latest) {
						t.Errorf("malformed request changed the list: %+v", got)
					}
					if id := pendingUndoID(t, s); id != "" {
						t.Errorf("malformed request recorded undo %q", id)
					}
					if audit := readUIAuditLog(s.cfg.StatePath, 20); len(audit) != 0 {
						t.Errorf("malformed request was audited: %+v", audit)
					}
				})
			}
		})
	}
}

func TestDismissAcceptsEmptyContentHash(t *testing.T) {
	s := newTestServerWithBbolt(t, "tok")
	f := listedYARAFinding(s, "/home/a/public_html/x.php", "")

	rec := postDismiss(t, s, map[string]any{"key": f.Key(), "contents": map[string]string{f.Key(): ""}})

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if e, _ := s.store.EntryForKey(f.Key()); !e.IsBaseline || e.ContentSHA256 != "" {
		t.Fatalf("finding without content was not dismissed: %+v", e)
	}
	if latest := s.store.LatestFindings(); len(latest) != 0 {
		t.Fatalf("dismissed finding remains listed: %+v", latest)
	}
}
