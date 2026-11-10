package webui

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

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
