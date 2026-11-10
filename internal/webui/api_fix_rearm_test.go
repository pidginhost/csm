package webui

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/checks"
)

// Fix and a resolved re-check remove the evidence. A later detection at the
// same path is a reinfection and must alert, not inherit an acknowledgment.
func TestResolvedFindingAlertsOnReturn(t *testing.T) {
	path := "/home/a/public_html/x.php"
	f := alert.Finding{Check: "world_writable_php", Message: "World-writable PHP: " + path, FilePath: path, Severity: alert.High}
	body := `{"check":"world_writable_php","message":"` + f.Message + `","file_path":"` + path + `","key":"` + f.Key() + `"}`
	for name, resolve := range map[string]func(*Server) int{
		"fix": func(s *Server) int {
			w := httptest.NewRecorder()
			s.apiFix(w, jsonPost("/api/v1/fix", body))
			return w.Code
		},
		"bulk fix": func(s *Server) int {
			w := httptest.NewRecorder()
			s.apiBulkFix(w, jsonPost("/api/v1/fix-bulk", "["+body+"]"))
			return w.Code
		},
		"verified resolved": func(s *Server) int {
			withVerdict(t, s, checks.VerifyResult{Checked: true, Resolved: true, Detail: "file removed"})
			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodPost, "/api/v1/verify-finding", strings.NewReader(body))
			r.Header.Set("Content-Type", "application/json")
			s.apiVerifyFinding(w, r)
			return w.Code
		},
	} {
		t.Run(name, func(t *testing.T) {
			s := newTestServer(t, "tok")
			s.applyFix = func(context.Context, string, string, string, ...string) checks.RemediationResult {
				return checks.RemediationResult{Success: true, Action: "chmod 644 " + path}
			}
			s.store.Update([]alert.Finding{f})
			s.store.SetLatestFindings([]alert.Finding{f})
			if code := resolve(s); code != http.StatusOK {
				t.Fatalf("status = %d", code)
			}
			if n := len(s.store.LatestFindings()); n != 0 {
				t.Fatalf("resolved finding still listed: %d", n)
			}
			if n := len(s.store.FilterNew([]alert.Finding{f})); n != 1 {
				t.Fatalf("return after %s suppressed: %d new", name, n)
			}
		})
	}
}

// A completed operation owns only the evidence it started with. Both halves
// of state must survive a refresh, even before that refresh reaches the list.
func TestResolutionPreservesConcurrentEvidence(t *testing.T) {
	for _, action := range []string{"fix", "bulk", "verify"} {
		for _, refresh := range []string{"scan", "realtime", "entry only", "dismiss"} {
			t.Run(action+"/"+refresh, func(t *testing.T) {
				s := newTestServer(t, "tok")
				f := alert.Finding{Check: "world_writable_php", Message: "Writable PHP", FilePath: "/home/alice/public_html/x.php", Severity: alert.High, Timestamp: time.Unix(100, 0)}
				s.store.Update([]alert.Finding{f})
				s.store.SetLatestFindings([]alert.Finding{f})
				var wantLatest []alert.Finding
				wantEntry, _ := s.store.EntryForKey(f.Key())
				change := func() {
					fresh := f
					fresh.Timestamp = f.Timestamp.Add(time.Second)
					switch refresh {
					case "scan":
						s.store.Update([]alert.Finding{fresh})
						s.store.PurgeAndMergeFindings([]string{f.Check}, []alert.Finding{fresh})
					case "realtime":
						s.store.SetLatestFindings([]alert.Finding{fresh})
					case "entry only":
						s.store.Update([]alert.Finding{fresh})
					case "dismiss":
						s.store.DismissFindingWithUndo(f.Key())
					}
					wantLatest = s.store.LatestFindings()
					entry, _ := s.store.EntryForKey(f.Key())
					wantEntry = entry
				}
				s.applyFix = func(context.Context, string, string, string, ...string) checks.RemediationResult {
					change()
					return checks.RemediationResult{Success: true}
				}
				s.verifyFinding = func(checks.VerifyInput) checks.VerifyResult {
					change()
					return checks.VerifyResult{Checked: true, Resolved: true}
				}
				body, err := json.Marshal(map[string]string{"check": f.Check, "message": f.Message, "key": f.Key()})
				if err != nil {
					t.Fatal(err)
				}
				w := httptest.NewRecorder()
				switch action {
				case "fix":
					s.apiFix(w, jsonPost("/", string(body)))
				case "bulk":
					s.apiBulkFix(w, jsonPost("/", "["+string(body)+"]"))
				case "verify":
					s.apiVerifyFinding(w, jsonPost("/", string(body)))
				}
				if w.Code != http.StatusOK {
					t.Fatalf("status = %d: %s", w.Code, w.Body.String())
				}
				if got := s.store.LatestFindings(); !reflect.DeepEqual(got, wantLatest) {
					t.Errorf("new evidence changed: got %+v, want %+v", got, wantLatest)
				}
				entry, ok := s.store.EntryForKey(f.Key())
				if !ok || !reflect.DeepEqual(entry, wantEntry) {
					t.Errorf("new alert state changed: %+v, present=%v", entry, ok)
				}
			})
		}
	}
}

func TestVerifyUnmatchedRequestCannotResolveStoredFinding(t *testing.T) {
	s := newTestServer(t, "tok")
	f := alert.Finding{Check: "webshell", Message: "Live file", FilePath: "/home/alice/public_html/live.php"}
	s.store.Update([]alert.Finding{f})
	s.store.SetLatestFindings([]alert.Finding{f})
	s.verifyFinding = func(checks.VerifyInput) checks.VerifyResult {
		return checks.VerifyResult{Checked: true, Resolved: true}
	}
	body, err := json.Marshal(map[string]string{"check": f.Check, "message": "different file", "file_path": "/home/alice/public_html/missing.php", "key": f.Key()})
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	s.apiVerifyFinding(w, jsonPost("/", string(body)))
	if got := s.store.LatestFindings(); len(got) != 1 || got[0].Key() != f.Key() {
		t.Fatalf("unmatched request cleared stored finding: %+v", got)
	}
	if _, ok := s.store.EntryForKey(f.Key()); !ok {
		t.Fatal("unmatched request cleared alert state")
	}
}

func TestFailedFixKeepsAlertState(t *testing.T) {
	for _, bulk := range []bool{false, true} {
		t.Run(map[bool]string{false: "fix", true: "bulk"}[bulk], func(t *testing.T) {
			s := newTestServer(t, "tok")
			f := alert.Finding{Check: "world_writable_php", Message: "Writable PHP"}
			s.store.Update([]alert.Finding{f})
			s.store.SetLatestFindings([]alert.Finding{f})
			before, _ := s.store.EntryForKey(f.Key())
			s.applyFix = func(context.Context, string, string, string, ...string) checks.RemediationResult {
				return checks.RemediationResult{Error: "refused"}
			}
			body := `{"check":"world_writable_php","message":"Writable PHP"}`
			w := httptest.NewRecorder()
			if bulk {
				s.apiBulkFix(w, jsonPost("/", "["+body+"]"))
			} else {
				s.apiFix(w, jsonPost("/", body))
			}
			wantStatus := http.StatusInternalServerError
			if bulk {
				wantStatus = http.StatusUnprocessableEntity
			}
			if w.Code != wantStatus {
				t.Fatalf("status=%d", w.Code)
			}
			if len(s.store.LatestFindings()) != 1 {
				t.Fatal("failed fix cleared listing")
			}
			after, ok := s.store.EntryForKey(f.Key())
			if !ok || !reflect.DeepEqual(before, after) {
				t.Fatal("failed fix changed alert state")
			}
		})
	}
}
