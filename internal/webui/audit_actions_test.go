package webui

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/emailav"
	"github.com/pidginhost/csm/internal/incident"
	"github.com/pidginhost/csm/internal/session"
)

func auditActions(t *testing.T, s *Server) []UIAuditEntry {
	t.Helper()
	return readUIAuditLog(s.cfg.StatePath, 100)
}

func requireAudit(t *testing.T, s *Server, action, target string) UIAuditEntry {
	t.Helper()
	for _, e := range auditActions(t, s) {
		if e.Action == action && (target == "" || e.Target == target) {
			return e
		}
	}
	t.Fatalf("no %q audit entry for %q; got %+v", action, target, auditActions(t, s))
	return UIAuditEntry{}
}

func jsonPost(path, body string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer tok")
	return r
}

func TestFirewallChangesAreAudited(t *testing.T) {
	s := newTestServer(t, "tok")
	fakeWhmapi1(t, 0)
	s.blocker = newFullBlocker()

	s.apiFirewallDenySubnet(httptest.NewRecorder(), jsonPost("/api/v1/firewall/deny-subnet", `{"cidr":"198.51.100.0/24","reason":"scanner","duration":"24h"}`))
	e := requireAudit(t, s, "firewall_deny_subnet", "198.51.100.0/24")
	if !strings.Contains(e.Details, "24h") || !strings.Contains(e.Details, "scanner") || e.Actor != "legacy-auth-token" {
		t.Errorf("deny-subnet entry = %+v", e)
	}
	s.apiFirewallRemoveSubnet(httptest.NewRecorder(), jsonPost("/api/v1/firewall/remove-subnet", `{"cidr":"198.51.100.0/24"}`))
	requireAudit(t, s, "firewall_remove_subnet", "198.51.100.0/24")
	s.apiFirewallRemoveAllow(httptest.NewRecorder(), jsonPost("/api/v1/firewall/remove-allow", `{"ip":"203.0.113.20"}`))
	requireAudit(t, s, "firewall_remove_allow", "203.0.113.20")
	s.apiFirewallFlushCphulk(httptest.NewRecorder(), jsonPost("/api/v1/firewall/cphulk-clear", `{"ip":"203.0.113.21"}`))
	requireAudit(t, s, "cphulk_clear", "203.0.113.21")
}

func TestEmailQuarantineDeleteIsAudited(t *testing.T) {
	s := newTestServer(t, "tok")
	dir := t.TempDir()
	s.SetEmailQuarantine(emailav.NewQuarantine(dir))
	if err := os.MkdirAll(filepath.Join(dir, "2jKPFm-000abc-1X"), 0o700); err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodDelete, "/api/v1/email/quarantine/2jKPFm-000abc-1X", nil)
	r.Header.Set("Authorization", "Bearer tok")
	w := httptest.NewRecorder()
	s.apiEmailQuarantineAction(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("delete = %d %s", w.Code, w.Body.String())
	}
	requireAudit(t, s, "email_quarantine_delete", "2jKPFm-000abc-1X")
}

func TestIncidentStatusChangeIsAudited(t *testing.T) {
	s := newTestServer(t, "tok")
	c := incident.NewCorrelator(incident.CorrelatorConfig{OpenThreshold: 1})
	id, _, err := c.OnFinding(alert.Finding{Severity: alert.Critical, Check: "mail_bruteforce", Message: "brute force from 203.0.113.99", SourceIP: "203.0.113.99", Timestamp: time.Now()})
	if err != nil || id == "" {
		t.Fatalf("OnFinding: %q %v", id, err)
	}
	s.SetIncidentCorrelator(c)
	w := httptest.NewRecorder()
	s.apiIncidentStatus(w, jsonPost("/api/v1/incidents/"+id+"/status", `{"status":"resolved","details":"password reset"}`))
	if w.Code != http.StatusOK {
		t.Fatalf("status change = %d %s", w.Code, w.Body.String())
	}
	e := requireAudit(t, s, "incident_status", id)
	if !strings.Contains(e.Details, "resolved") {
		t.Errorf("incident entry = %+v", e)
	}
}

func TestScanJobChangesAreAudited(t *testing.T) {
	s, adminTok, _, fake := newTestServerWithFakeScanJobs(t)
	fake.enqueueID = "sj-0001"
	r := httptest.NewRequest(http.MethodPost, "/api/v1/scan-jobs", strings.NewReader(`{"scope":"account","target":"alice","quarantine":true}`))
	r.Header.Set("Authorization", "Bearer "+adminTok)
	s.apiScanJobsEnqueue(httptest.NewRecorder(), r)
	e := requireAudit(t, s, "scan_job_enqueue", "alice")
	if !strings.Contains(e.Details, "sj-0001") || !strings.Contains(e.Details, "quarantine=true") {
		t.Errorf("enqueue entry = %+v", e)
	}
	r = httptest.NewRequest(http.MethodPost, "/api/v1/scan-jobs/sj-0001/cancel", nil)
	r.Header.Set("Authorization", "Bearer "+adminTok)
	s.apiScanJobsCancel(httptest.NewRecorder(), r)
	requireAudit(t, s, "scan_job_cancel", "sj-0001")
}

func TestBulkFixAuditsEachAppliedFix(t *testing.T) {
	s := newTestServer(t, "tok")
	f := alert.Finding{Check: "world_writable_php", Message: "World-writable PHP: /home/a/x.php", FilePath: "/home/a/x.php"}
	s.store.SetLatestFindings([]alert.Finding{f})
	s.applyFix = func(_ context.Context, check, _, _ string, _ ...string) checks.RemediationResult {
		return checks.RemediationResult{Success: true, Action: "chmod 644 /home/a/x.php"}
	}
	body := `[{"check":"world_writable_php","message":"World-writable PHP: /home/a/x.php","file_path":"/home/a/x.php","key":"` + f.Key() + `"}]`
	w := httptest.NewRecorder()
	s.apiBulkFix(w, jsonPost("/api/v1/fix-bulk", body))
	if w.Code != http.StatusOK {
		t.Fatalf("bulk fix = %d %s", w.Code, w.Body.String())
	}
	e := requireAudit(t, s, "fix", "world_writable_php")
	if e.Details != "chmod 644 /home/a/x.php" {
		t.Errorf("fix entry = %+v", e)
	}
}

func TestSessionLifecycleIsAudited(t *testing.T) {
	s := newTestServer(t, "")
	token := "alice-admin-token-0123456789abcdef"
	s.cfg.WebUI.Tokens = []config.WebUIToken{{Name: "alice", Token: token, Scope: "admin"}}

	// Login.
	form := url.Values{"token": {token}}
	r := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	s.handleLogin(w, r)
	if w.Code != http.StatusFound {
		t.Fatalf("login = %d", w.Code)
	}
	e := requireAudit(t, s, "login", "alice")
	if e.Actor != "alice" || e.Via != "browser" {
		t.Errorf("login entry = %+v", e)
	}
	var cookie *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == "csm_auth" {
			cookie = c
		}
	}
	if cookie == nil {
		t.Fatal("no session cookie")
	}

	// Revoking another session names the actor even though it is not the target.
	_, other, err := s.sessions.Create("alice", session.Hash(token), "", "192.0.2.11", "other", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	r = httptest.NewRequest(http.MethodDelete, "/api/v1/sessions/"+other.ID, nil)
	r.AddCookie(cookie)
	s.apiSessions(httptest.NewRecorder(), r)
	e = requireAudit(t, s, "session_revoke", other.ID)
	if e.Actor != "alice" {
		t.Errorf("revoke entry = %+v", e)
	}

	// Logout ends the session and is still attributed to it.
	r = httptest.NewRequest(http.MethodPost, "/logout", nil)
	r.AddCookie(cookie)
	s.handleLogout(httptest.NewRecorder(), r)
	e = requireAudit(t, s, "logout", "alice")
	if e.Actor != "alice" {
		t.Errorf("logout entry = %+v", e)
	}
}

func TestFailedUndoIsAudited(t *testing.T) {
	s := newTestServerWithBbolt(t, "tok")
	s.blocker = nil
	id := s.recordUndoEntry(bearerRequest("POST", "/api/v1/undo/run", nil),
		"firewall_bulk_unblock", undoInverseFirewallUnblock, "Unblocked 1 IP",
		undoPayloadIPs{IPs: []string{"203.0.113.50"}})
	if id == "" {
		t.Fatal("no undo entry")
	}
	w := httptest.NewRecorder()
	s.apiUndoRun(w, bearerRequest("POST", "/api/v1/undo/run", []byte(`{"id":"`+id+`"}`)))
	if w.Code == http.StatusOK {
		t.Fatalf("undo without a firewall engine succeeded: %s", w.Body.String())
	}
	e := requireAudit(t, s, "undo_firewall_bulk_unblock_failed", "203.0.113.50")
	if e.Details == "" {
		t.Errorf("failed undo entry = %+v", e)
	}
}
