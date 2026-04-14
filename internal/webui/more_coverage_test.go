package webui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/emailav"
	"github.com/pidginhost/csm/internal/firewall"
)

// =========================================================================
// hardening_api.go — additional branches
// =========================================================================

// apiHardeningRun POST without bbolt store skips the save branch entirely
// and returns the in-memory audit report. Verifies the no-DB code path.
func TestAPIHardeningRunPOSTNoStore(t *testing.T) {
	s := newTestServer(t, "tok")
	// Ensure no global store.
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", nil)
	s.apiHardeningRun(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
	// Body should be a JSON object containing the report fields.
	body := w.Body.String()
	if !strings.Contains(body, "server_type") || !strings.Contains(body, "results") {
		t.Errorf("body missing expected fields: %s", body)
	}
}

// apiHardeningRun PUT/DELETE/etc are rejected with 405.
func TestAPIHardeningRunRejectsPUT(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	s.apiHardeningRun(w, httptest.NewRequest("PUT", "/", nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("PUT = %d, want 405", w.Code)
	}
}

// apiHardeningRun DELETE rejected with 405.
func TestAPIHardeningRunRejectsDELETE(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	s.apiHardeningRun(w, httptest.NewRequest("DELETE", "/", nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("DELETE = %d, want 405", w.Code)
	}
}

// =========================================================================
// performance_api.go — apiPerformance with EntryForKey hits + sort
// =========================================================================

// Exercises the EntryForKey lookup branch — when a finding has a stored
// entry, FirstSeen comes from the entry, not the finding's own timestamp.
func TestAPIPerformanceUsesEntryForKey(t *testing.T) {
	s := newTestServer(t, "tok")
	now := time.Now()
	earlier := now.Add(-2 * time.Hour)

	// First seed the store so EntryForKey returns a hit.
	original := []alert.Finding{
		{Severity: alert.Warning, Check: "perf_memory", Message: "mem high",
			Timestamp: earlier},
	}
	s.store.SetLatestFindings(original)

	// Then inject the same key so EntryForKey lookup succeeds.
	s.store.SetLatestFindings([]alert.Finding{
		{Severity: alert.Warning, Check: "perf_memory", Message: "mem high",
			Timestamp: now},
	})

	w := httptest.NewRecorder()
	s.apiPerformance(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}

	var resp perfResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("json: %v", err)
	}
	if len(resp.Findings) == 0 {
		t.Fatal("expected at least one perf finding")
	}
	// FirstSeen should be a parseable RFC3339 timestamp.
	if _, err := time.Parse(time.RFC3339, resp.Findings[0].FirstSeen); err != nil {
		t.Errorf("FirstSeen not RFC3339: %v (got %q)", err, resp.Findings[0].FirstSeen)
	}
}

// Verifies severity sort ordering when multiple severities appear.
func TestAPIPerformanceSortsBySeverityDesc(t *testing.T) {
	s := newTestServer(t, "tok")
	now := time.Now()
	s.store.SetLatestFindings([]alert.Finding{
		{Severity: alert.Warning, Check: "perf_memory", Message: "mem warn", Timestamp: now},
		{Severity: alert.Critical, Check: "perf_disk", Message: "disk full", Timestamp: now},
		{Severity: alert.High, Check: "perf_load", Message: "load high", Timestamp: now},
	})

	w := httptest.NewRecorder()
	s.apiPerformance(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	var resp perfResponse
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if len(resp.Findings) != 3 {
		t.Fatalf("findings = %d, want 3", len(resp.Findings))
	}
	for i := 1; i < len(resp.Findings); i++ {
		if resp.Findings[i-1].Severity < resp.Findings[i].Severity {
			t.Errorf("sort order broken at index %d: %d < %d",
				i, resp.Findings[i-1].Severity, resp.Findings[i].Severity)
		}
	}
}

// apiPerformance with a default limit (no limit query param).
func TestAPIPerformanceDefaultLimit(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	s.apiPerformance(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	var resp perfResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("json: %v", err)
	}
	// Should return Findings field even if empty (initialized as nil-safe).
	_ = resp.Findings
}

// =========================================================================
// email_api.go — apiEmailQuarantineList error + apiEmailStats deeper
// =========================================================================

// apiEmailQuarantineList returns 500 when the underlying baseDir is a
// regular file (ReadDir fails with ENOTDIR).
func TestAPIEmailQuarantineListReadDirFails(t *testing.T) {
	s := newTestServer(t, "tok")

	dir := t.TempDir()
	notADir := filepath.Join(dir, "imafile")
	if err := os.WriteFile(notADir, []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	s.emailQuarantine = emailav.NewQuarantine(notADir)

	w := httptest.NewRecorder()
	s.apiEmailQuarantineList(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

// apiEmailStats with a nil firewall config has nil-safe defaults via the
// struct literal init — this verifies the various pieces handle empty.
func TestAPIEmailStatsNoFirewallPortsOrUsers(t *testing.T) {
	s := newTestServer(t, "tok")
	s.cfg.Firewall = &firewall.FirewallConfig{
		// All fields zero/nil
	}

	w := httptest.NewRecorder()
	s.apiEmailStats(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	var resp emailStatsResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("json: %v", err)
	}
	// All slice fields must be empty-initialized, not null.
	if resp.SMTPAllowUsers == nil || resp.SMTPPorts == nil || resp.PortFlood == nil {
		t.Errorf("nil slices in response: %+v", resp)
	}
	// QueueWarn / QueueCrit come from cfg.Thresholds defaults (likely 0).
	if resp.QueueSize < 0 {
		t.Errorf("QueueSize = %d", resp.QueueSize)
	}
}

// apiEmailStats: warn/crit thresholds appear in the response.
func TestAPIEmailStatsThresholds(t *testing.T) {
	s := newTestServer(t, "tok")
	s.cfg.Firewall = &firewall.FirewallConfig{}
	s.cfg.Thresholds.MailQueueWarn = 100
	s.cfg.Thresholds.MailQueueCrit = 500

	w := httptest.NewRecorder()
	s.apiEmailStats(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	var resp emailStatsResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("json: %v", err)
	}
	if resp.QueueWarn != 100 {
		t.Errorf("QueueWarn = %d, want 100", resp.QueueWarn)
	}
	if resp.QueueCrit != 500 {
		t.Errorf("QueueCrit = %d, want 500", resp.QueueCrit)
	}
}

// apiEmailQuarantineAction GET with non-existent message ID returns 404.
func TestAPIEmailQuarantineActionGETNonexistentID(t *testing.T) {
	s := newTestServer(t, "tok")
	dir := t.TempDir()
	s.emailQuarantine = emailav.NewQuarantine(dir)

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/v1/email/quarantine/no-such-id", nil)
	s.apiEmailQuarantineAction(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

// apiEmailQuarantineAction POST with unknown action returns 400.
func TestAPIEmailQuarantineActionPOSTUnknownAction(t *testing.T) {
	s := newTestServer(t, "tok")
	dir := t.TempDir()
	s.emailQuarantine = emailav.NewQuarantine(dir)

	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/v1/email/quarantine/abc/deflate", nil)
	s.apiEmailQuarantineAction(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
	if !strings.Contains(w.Body.String(), "release") {
		t.Errorf("body should hint at release: %s", w.Body.String())
	}
}

// apiEmailQuarantineAction POST release on a non-existent message returns 500
// (ReleaseMessage fails to read metadata).
func TestAPIEmailQuarantineActionPOSTReleaseNonexistent(t *testing.T) {
	s := newTestServer(t, "tok")
	dir := t.TempDir()
	s.emailQuarantine = emailav.NewQuarantine(dir)

	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/v1/email/quarantine/missing/release", nil)
	s.apiEmailQuarantineAction(w, req)
	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

// apiEmailQuarantineAction PUT (unknown method) returns 405.
func TestAPIEmailQuarantineActionPUTRejected(t *testing.T) {
	s := newTestServer(t, "tok")
	dir := t.TempDir()
	s.emailQuarantine = emailav.NewQuarantine(dir)

	w := httptest.NewRecorder()
	req := httptest.NewRequest("PUT", "/api/v1/email/quarantine/abc", nil)
	s.apiEmailQuarantineAction(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", w.Code)
	}
}

// apiEmailQuarantineAction with bare msgID == "." (filepath.Base of "./")
// is rejected with 400.
func TestAPIEmailQuarantineActionDotMsgID(t *testing.T) {
	s := newTestServer(t, "tok")
	dir := t.TempDir()
	s.emailQuarantine = emailav.NewQuarantine(dir)

	w := httptest.NewRecorder()
	// Path resolves to "." which the handler explicitly rejects.
	req := httptest.NewRequest("GET", "/api/v1/email/quarantine/.", nil)
	s.apiEmailQuarantineAction(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

// =========================================================================
// handlers — handleAccount / handleIncident / handleAudit deeper paths
// =========================================================================

// handleAccount with seeded findings, history and quarantine metadata
// renders successfully and exercises the data assembly path via the
// related apiAccountDetail call.
func TestHandleAccountWithSeededDataRenders(t *testing.T) {
	s := newTestServerWithTemplates(t, "tok")
	s.cfg.Hostname = "test.example.com"
	now := time.Now()

	s.store.SetLatestFindings([]alert.Finding{
		{Severity: alert.Critical, Check: "webshell",
			Message:   "Found /home/eve/public_html/shell.php",
			Timestamp: now},
	})
	s.store.AppendHistory([]alert.Finding{
		{Severity: alert.High, Check: "obfuscated_php",
			Message: "obf in /home/eve/x.php", Timestamp: now},
	})

	w := httptest.NewRecorder()
	s.handleAccount(w, httptest.NewRequest("GET", "/?name=eve", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
}

// handleAccount with an account name that fails validation due to
// length redirects to /findings.
func TestHandleAccountTooLongRedirects(t *testing.T) {
	s := newTestServerWithTemplates(t, "tok")
	w := httptest.NewRecorder()
	long := strings.Repeat("a", 65)
	s.handleAccount(w, httptest.NewRequest("GET", "/?name="+long, nil))
	if w.Code != http.StatusFound {
		t.Errorf("status = %d, want 302", w.Code)
	}
	if w.Header().Get("Location") != "/findings" {
		t.Errorf("location = %q", w.Header().Get("Location"))
	}
}

// handleIncident renders the static template; downstream apiIncident
// is the one that consumes ip/account params. Confirm no error when
// the page is requested with various unrelated query strings.
func TestHandleIncidentWithQueryParams(t *testing.T) {
	s := newTestServerWithTemplates(t, "tok")
	w := httptest.NewRecorder()
	s.handleIncident(w, httptest.NewRequest(
		"GET", "/?ip=203.0.113.1&account=foo&hours=48", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	if w.Body.String() != "OK" {
		t.Errorf("body = %q", w.Body.String())
	}
}

// handleAudit renders even when no audit log exists on disk.
func TestHandleAuditNoLog(t *testing.T) {
	s := newTestServerWithTemplates(t, "tok")
	w := httptest.NewRecorder()
	s.handleAudit(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
}

// apiUIAudit returns the entries that have been appended to the audit
// log file, newest-first.
func TestAPIUIAuditWithEntries(t *testing.T) {
	s := newTestServer(t, "tok")

	path := filepath.Join(s.cfg.StatePath, uiAuditFile)
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	enc := json.NewEncoder(f)
	for i := 0; i < 3; i++ {
		_ = enc.Encode(UIAuditEntry{
			Timestamp: time.Now().Add(-time.Duration(i) * time.Minute),
			Action:    "block",
			Target:    "203.0.113." + string(rune('1'+i)),
			Details:   "test entry",
			SourceIP:  "10.0.0.1",
		})
	}
	_ = f.Close()

	w := httptest.NewRecorder()
	s.apiUIAudit(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	var entries []UIAuditEntry
	if err := json.Unmarshal(w.Body.Bytes(), &entries); err != nil {
		t.Fatalf("json: %v", err)
	}
	if len(entries) != 3 {
		t.Errorf("entries = %d, want 3", len(entries))
	}
}

// apiUIAudit returns an empty array (not null) when the log file
// is missing.
func TestAPIUIAuditEmptyArrayWhenMissing(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	s.apiUIAudit(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	body := strings.TrimSpace(w.Body.String())
	if body != "[]" {
		t.Errorf("body = %q, want []", body)
	}
}

// =========================================================================
// topMailSenders — small log file at the absolute path is the only way
// to drive coverage. We only run this if the file is creatable, otherwise
// skip. On most CI runners /var/log isn't writeable as non-root.
// =========================================================================

func TestTopMailSendersWithLogFile(t *testing.T) {
	const logPath = "/var/log/exim_mainlog"
	// Try to write a small log file. Skip on permission denied.
	content := []byte(
		"2026-04-14 10:00:00 1abc-001 <= alice@example.com U=alice P=local S=512\n" +
			"2026-04-14 10:00:01 1abc-002 <= bob@example.org U=bob P=local S=600\n" +
			"2026-04-14 10:00:02 1abc-003 <= alice@example.com U=alice P=local S=720\n" +
			"2026-04-14 10:00:03 1abc-004 <= <> U=root P=local S=400\n" +
			"2026-04-14 10:00:04 1abc-005 <= cPanel@example.org U=root P=local S=400\n" +
			"2026-04-14 10:00:05 1abc-006 <= no-at-sign U=foo P=local S=300\n",
	)
	// Preserve any existing file.
	var backup []byte
	hadFile := false
	if data, err := os.ReadFile(logPath); err == nil {
		backup = data
		hadFile = true
	}
	if err := os.WriteFile(logPath, content, 0644); err != nil {
		t.Skipf("cannot write %s (need root): %v", logPath, err)
	}
	t.Cleanup(func() {
		if hadFile {
			_ = os.WriteFile(logPath, backup, 0644)
		} else {
			_ = os.Remove(logPath)
		}
	})

	got := topMailSenders(500, 10)
	if got == nil {
		t.Fatal("expected non-nil result")
	}
	// example.com should be top with 2 messages, example.org with 1.
	foundExampleCom := false
	for _, e := range got {
		if e.Domain == "example.com" {
			foundExampleCom = true
			if e.Count < 2 {
				t.Errorf("example.com count = %d, want >=2", e.Count)
			}
		}
		// cPanel-prefixed sender and bounce <> must be skipped.
		if e.Domain == "" {
			t.Error("empty domain returned")
		}
	}
	if !foundExampleCom {
		t.Errorf("expected example.com in results: %+v", got)
	}
}
