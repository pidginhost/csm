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
	"github.com/pidginhost/csm/internal/state"
	"github.com/pidginhost/csm/internal/store"
)

// =========================================================================
// performance_api.go — deeper apiPerformance branches
// =========================================================================

// Seeds perf_ findings and verifies they are returned and sorted by severity.
func TestAPIPerformanceReturnsPerfFindings(t *testing.T) {
	s := newTestServer(t, "tok")
	m := &perfMetrics{CPUCores: 2, Uptime: "5d 1h"}
	s.perfSnapshot.Store(m)

	now := time.Now()
	s.store.SetLatestFindings([]alert.Finding{
		{Severity: alert.Warning, Check: "perf_memory", Message: "mem high", Timestamp: now},
		{Severity: alert.Critical, Check: "perf_load", Message: "load critical", Timestamp: now},
		{Severity: alert.High, Check: "perf_swap", Message: "swap busy", Timestamp: now},
		// Non-perf finding should be skipped
		{Severity: alert.Critical, Check: "webshell", Message: "skip me", Timestamp: now},
	})

	w := httptest.NewRecorder()
	s.apiPerformance(w, httptest.NewRequest("GET", "/?limit=10", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}

	var resp perfResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("json: %v", err)
	}
	if len(resp.Findings) != 3 {
		t.Errorf("perf findings = %d, want 3", len(resp.Findings))
	}
	// Sorted by severity descending, so Critical first
	if len(resp.Findings) >= 1 && resp.Findings[0].Check != "perf_load" {
		t.Errorf("first finding check = %q, want perf_load (highest severity)", resp.Findings[0].Check)
	}
}

// Limit truncation when perf findings exceed the requested limit.
func TestAPIPerformanceTruncatesToLimit(t *testing.T) {
	s := newTestServer(t, "tok")

	now := time.Now()
	var findings []alert.Finding
	for i := 0; i < 5; i++ {
		findings = append(findings, alert.Finding{
			Severity:  alert.Warning,
			Check:     "perf_memory",
			Message:   "mem warn",
			Details:   string(rune('a' + i)),
			Timestamp: now,
		})
	}
	s.store.SetLatestFindings(findings)

	w := httptest.NewRecorder()
	s.apiPerformance(w, httptest.NewRequest("GET", "/?limit=2", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	var resp perfResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("json: %v", err)
	}
	if len(resp.Findings) != 2 {
		t.Errorf("truncated findings = %d, want 2", len(resp.Findings))
	}
}

// Suppressed findings are filtered out of the perf response.
func TestAPIPerformanceSkipsSuppressed(t *testing.T) {
	s := newTestServer(t, "tok")

	now := time.Now()
	s.store.SetLatestFindings([]alert.Finding{
		{Severity: alert.Warning, Check: "perf_memory", Message: "mem high", Timestamp: now},
		{Severity: alert.Warning, Check: "perf_swap", Message: "swap tuning", Timestamp: now},
	})
	// Suppress perf_memory
	_ = s.store.SaveSuppressions([]state.SuppressionRule{
		{Check: "perf_memory"},
	})

	w := httptest.NewRecorder()
	s.apiPerformance(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	var resp perfResponse
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	for _, f := range resp.Findings {
		if f.Check == "perf_memory" {
			t.Errorf("suppressed finding present: %+v", f)
		}
	}
}

// =========================================================================
// hardening_api.go — apiHardening / apiHardeningRun branches
// =========================================================================

// apiHardening returns a saved report when the bbolt store has one.
func TestAPIHardeningReturnsSavedReport(t *testing.T) {
	s := newTestServerWithBbolt(t, "tok")
	db := store.Global()
	if db == nil {
		t.Fatal("store.Global() is nil")
	}
	report := &store.AuditReport{
		Timestamp:  time.Now(),
		ServerType: "almalinux",
		Score:      42,
		Total:      100,
		Results: []store.AuditResult{
			{Category: "ssh", Name: "ssh_root", Title: "SSH root login", Status: "fail", Message: "permitted"},
		},
	}
	if err := db.SaveHardeningReport(report); err != nil {
		t.Fatal(err)
	}

	w := httptest.NewRecorder()
	s.apiHardening(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	var out store.AuditReport
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("json: %v", err)
	}
	if out.ServerType != "almalinux" {
		t.Errorf("ServerType = %q", out.ServerType)
	}
	if out.Score != 42 {
		t.Errorf("Score = %d, want 42", out.Score)
	}
}

// When there is no global bbolt store, apiHardening returns a zero AuditReport.
func TestAPIHardeningNoGlobalStore(t *testing.T) {
	s := newTestServer(t, "tok")
	store.SetGlobal(nil)

	w := httptest.NewRecorder()
	s.apiHardening(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "{") {
		t.Errorf("expected JSON object, got %q", w.Body.String())
	}
}

// =========================================================================
// handlers.go — handleDashboard details branch + handleFindings / handleQuarantine
// =========================================================================

// handleDashboard with a critical finding — exercises lastCriticalAgo != "None".
func TestHandleDashboardShowsLastCritical(t *testing.T) {
	s := newTestServerWithTemplates(t, "tok")
	now := time.Now()
	s.store.AppendHistory([]alert.Finding{
		{Severity: alert.Critical, Check: "webshell", Message: "shell found", Details: "c99", Timestamp: now},
		{Severity: alert.High, Check: "obfuscated_php", Message: "pack", Timestamp: now.Add(-10 * time.Minute)},
	})

	w := httptest.NewRecorder()
	s.handleDashboard(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
}

// handleFindings injects the Hostname into the template data map.
func TestHandleFindingsSetsHostname(t *testing.T) {
	s := newTestServerWithTemplates(t, "tok")
	s.cfg.Hostname = "unit-test-host"

	w := httptest.NewRecorder()
	s.handleFindings(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
}

// handleQuarantine renders even with zero files.
func TestHandleQuarantineEmpty(t *testing.T) {
	s := newTestServerWithTemplates(t, "tok")
	w := httptest.NewRecorder()
	s.handleQuarantine(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
}

// handleHistoryRedirect with a trailing ampersand-style query string.
func TestHandleHistoryRedirectPreservesMultiParam(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/history?check=abc&severity=2", nil)
	s.handleHistoryRedirect(w, req)
	if w.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", w.Code)
	}
	loc := w.Header().Get("Location")
	if !strings.Contains(loc, "tab=history") || !strings.Contains(loc, "check=abc") || !strings.Contains(loc, "severity=2") {
		t.Errorf("Location = %q missing expected params", loc)
	}
}

// =========================================================================
// email_api.go — deeper branches
// =========================================================================

// SMTPPorts contain 465 (flood rule), and SMTPAllowUsers explicitly populated.
func TestAPIEmailStatsSMTPPort465Flood(t *testing.T) {
	s := newTestServer(t, "tok")
	s.cfg.Firewall = &firewall.FirewallConfig{
		SMTPBlock:      false,
		SMTPAllowUsers: []string{"mailman", "root"},
		SMTPPorts:      []int{465},
		PortFlood: []firewall.PortFloodRule{
			{Port: 465, Proto: "tcp", Hits: 5, Seconds: 30},
			{Port: 587, Proto: "tcp", Hits: 10, Seconds: 60},
			{Port: 22, Proto: "tcp", Hits: 100, Seconds: 60}, // non-SMTP excluded
		},
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
	// Port 22 excluded, ports 465 + 587 included
	if len(resp.PortFlood) != 2 {
		t.Errorf("port_flood len = %d, want 2", len(resp.PortFlood))
	}
	if len(resp.SMTPAllowUsers) != 2 {
		t.Errorf("smtp_allow_users len = %d, want 2", len(resp.SMTPAllowUsers))
	}
}

// apiEmailQuarantineAction POST release with quarantine containing a real message.
func TestAPIEmailQuarantineActionDeleteRealMessage(t *testing.T) {
	s := newTestServer(t, "tok")
	dir := t.TempDir()
	s.emailQuarantine = emailav.NewQuarantine(dir)

	// Pre-create a quarantine message subdir (the Quarantine treats it as message id)
	msgDir := filepath.Join(dir, "msg999")
	if err := os.MkdirAll(msgDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(msgDir, "meta.json"), []byte("{}"), 0644); err != nil {
		t.Fatal(err)
	}

	w := httptest.NewRecorder()
	req := httptest.NewRequest("DELETE", "/api/v1/email/quarantine/msg999", nil)
	s.apiEmailQuarantineAction(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("DELETE = %d, body = %s", w.Code, w.Body.String())
	}
	// Verify directory is gone
	if _, err := os.Stat(msgDir); !os.IsNotExist(err) {
		t.Errorf("msg dir still exists after delete: %v", err)
	}
}

// Path with traversal attempt: /api/v1/email/quarantine/../../etc/passwd
// filepath.Base sanitizes it to "passwd", which then 404s as not found.
func TestAPIEmailQuarantineActionTraversalSanitized(t *testing.T) {
	s := newTestServer(t, "tok")
	dir := t.TempDir()
	s.emailQuarantine = emailav.NewQuarantine(dir)

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/v1/email/quarantine/../../etc/passwd", nil)
	s.apiEmailQuarantineAction(w, req)
	// Should not succeed — path sanitization ensures lookup targets a benign name
	if w.Code == http.StatusOK {
		t.Errorf("traversal succeeded unexpectedly: code = %d", w.Code)
	}
}

// =========================================================================
// rules_api.go — apiRulesList error + apiModSecEscalation GET/POST branches
// =========================================================================

// apiRulesList returns 500 when the directory path is a file (read error).
func TestAPIRulesListReturnsErrorForNonDir(t *testing.T) {
	s := newTestServer(t, "tok")
	// Create a plain file where a directory is expected
	dir := t.TempDir()
	notADir := filepath.Join(dir, "not-a-dir")
	if err := os.WriteFile(notADir, []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	s.cfg.Signatures.RulesDir = notADir

	w := httptest.NewRecorder()
	s.apiRulesList(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

// apiRulesReload rejects GET method.
func TestAPIRulesReloadMethodNotAllowed(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	s.apiRulesReload(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET reload = %d, want 405", w.Code)
	}
}

// apiModSecEscalation GET returns empty rules list when no store.
func TestAPIModSecEscalationGETNoStore(t *testing.T) {
	s := newTestServer(t, "tok")
	store.SetGlobal(nil)

	w := httptest.NewRecorder()
	s.apiModSecEscalation(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("json: %v", err)
	}
	rules, _ := resp["rules"].([]interface{})
	if rules == nil {
		t.Error("rules should be [] not nil")
	}
	if len(rules) != 0 {
		t.Errorf("rules len = %d, want 0", len(rules))
	}
}

// apiModSecEscalation POST with valid rules list (bbolt store).
func TestAPIModSecEscalationPOSTSavesRules(t *testing.T) {
	s := newTestServerWithBbolt(t, "tok")

	body := `{"rules":[900001,900002,900003]}`
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	s.apiModSecEscalation(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("json: %v", err)
	}
	if resp["ok"] != true {
		t.Errorf("ok = %v", resp["ok"])
	}
	if resp["count"].(float64) != 3 {
		t.Errorf("count = %v, want 3", resp["count"])
	}

	// Subsequent GET should return the 3 rules.
	w2 := httptest.NewRecorder()
	s.apiModSecEscalation(w2, httptest.NewRequest("GET", "/", nil))
	if w2.Code != http.StatusOK {
		t.Fatalf("GET status = %d", w2.Code)
	}
	var got map[string]interface{}
	if err := json.Unmarshal(w2.Body.Bytes(), &got); err != nil {
		t.Fatalf("GET json: %v", err)
	}
	rules, _ := got["rules"].([]interface{})
	if len(rules) != 3 {
		t.Errorf("GET rules len = %d, want 3", len(rules))
	}
}

// apiModSecEscalation POST with no store returns 500.
func TestAPIModSecEscalationPOSTNoStore(t *testing.T) {
	s := newTestServer(t, "tok")
	store.SetGlobal(nil)

	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", strings.NewReader(`{"rules":[900001]}`))
	req.Header.Set("Content-Type", "application/json")
	s.apiModSecEscalation(w, req)
	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

// apiModSecEscalation POST with malformed JSON.
func TestAPIModSecEscalationPOSTBadJSON(t *testing.T) {
	s := newTestServerWithBbolt(t, "tok")

	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", strings.NewReader(`{bad`))
	req.Header.Set("Content-Type", "application/json")
	s.apiModSecEscalation(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

// =========================================================================
// incident_api.go — deeper paths
// =========================================================================

// Incident API filters by cutoff: too-old finding is excluded.
func TestAPIIncidentFiltersByCutoff(t *testing.T) {
	s := newTestServerWithBbolt(t, "tok")

	old := time.Now().Add(-100 * 24 * time.Hour) // ~100 days old
	recent := time.Now().Add(-1 * time.Hour)

	s.store.AppendHistory([]alert.Finding{
		{Severity: alert.Critical, Check: "brute_force", Message: "SSH from 203.0.113.5", Timestamp: old},
		{Severity: alert.High, Check: "brute_force", Message: "SSH from 203.0.113.5 repeated", Timestamp: recent},
	})

	// Use hours=24 — only recent finding is in scope
	w := httptest.NewRecorder()
	s.apiIncident(w, httptest.NewRequest("GET", "/?ip=203.0.113.5&hours=24", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("json: %v", err)
	}
	total, _ := resp["total"].(float64)
	if total != 1 {
		t.Errorf("total = %v, want 1 (old finding should be excluded by cutoff)", total)
	}
}

// Incident API combines IP + account, merging matches from both search terms.
func TestAPIIncidentBothIPAndAccount(t *testing.T) {
	s := newTestServerWithBbolt(t, "tok")
	now := time.Now()

	s.store.AppendHistory([]alert.Finding{
		{Severity: alert.Critical, Check: "webshell", Message: "shell from 203.0.113.5 in /home/alice/x.php", Timestamp: now},
		{Severity: alert.High, Check: "brute_force", Message: "SSH from 203.0.113.5", Timestamp: now},
		{Severity: alert.Warning, Check: "other", Message: "untouched", Timestamp: now},
	})

	w := httptest.NewRecorder()
	s.apiIncident(w, httptest.NewRequest("GET", "/?ip=203.0.113.5&account=alice", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	var resp map[string]interface{}
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["query_ip"] != "203.0.113.5" || resp["query_account"] != "alice" {
		t.Errorf("query params echoed wrong: %+v", resp)
	}
	total, _ := resp["total"].(float64)
	if total < 2 {
		t.Errorf("total = %v, want >=2", total)
	}
}

// Incident API also reads UI audit log entries and emits them as "action" events.
func TestAPIIncidentIncludesAuditActions(t *testing.T) {
	s := newTestServer(t, "tok")

	// Write a matching audit entry to the log
	dir := s.cfg.StatePath
	path := filepath.Join(dir, uiAuditFile)
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	enc := json.NewEncoder(f)
	_ = enc.Encode(UIAuditEntry{
		Timestamp: time.Now(),
		Action:    "block",
		Target:    "203.0.113.5",
		Details:   "manual",
		SourceIP:  "10.0.0.1",
	})
	// Unrelated entry that should NOT match
	_ = enc.Encode(UIAuditEntry{
		Timestamp: time.Now(),
		Action:    "dismiss",
		Target:    "something_else",
		Details:   "not related",
		SourceIP:  "10.0.0.1",
	})
	_ = f.Close()

	w := httptest.NewRecorder()
	s.apiIncident(w, httptest.NewRequest("GET", "/?ip=203.0.113.5", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	var resp struct {
		Events []struct {
			Type   string `json:"type"`
			Source string `json:"source"`
		} `json:"events"`
		Total int `json:"total"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("json: %v", err)
	}
	foundAction := false
	for _, ev := range resp.Events {
		if ev.Type == "action" && ev.Source == "audit" {
			foundAction = true
		}
	}
	if !foundAction {
		t.Errorf("expected action/audit event in response, got events = %+v", resp.Events)
	}
}

// =========================================================================
// threat_api.go — remaining branches (invalid IP validation on POST endpoints)
// =========================================================================

// apiThreatWhitelistIP rejects malformed JSON body.
func TestAPIThreatWhitelistIPBadJSON(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", strings.NewReader(`{not json`))
	req.Header.Set("Content-Type", "application/json")
	s.apiThreatWhitelistIP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("bad JSON = %d, want 400", w.Code)
	}
}

// apiThreatWhitelistIP rejects an invalid IP string.
func TestAPIThreatWhitelistIPInvalidIP(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", strings.NewReader(`{"ip":"not-an-ip"}`))
	req.Header.Set("Content-Type", "application/json")
	s.apiThreatWhitelistIP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("bad IP = %d, want 400", w.Code)
	}
}

// apiThreatUnwhitelistIP also rejects invalid IPs.
func TestAPIThreatUnwhitelistIPInvalidIP(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", strings.NewReader(`{"ip":"127.0.0.1"}`))
	req.Header.Set("Content-Type", "application/json")
	s.apiThreatUnwhitelistIP(w, req)
	// Loopback fails parseAndValidateIP
	if w.Code != http.StatusBadRequest {
		t.Errorf("loopback = %d, want 400", w.Code)
	}
}

// apiThreatBlockIP with no blocker returns 503.
func TestAPIThreatBlockIPNoBlocker(t *testing.T) {
	s := newTestServer(t, "tok")
	s.blocker = nil
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", strings.NewReader(`{"ip":"203.0.113.5"}`))
	req.Header.Set("Content-Type", "application/json")
	s.apiThreatBlockIP(w, req)
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("no blocker = %d, want 503", w.Code)
	}
}

// apiThreatClearIP with valid IP + no blocker returns "cleared" (no-op path).
func TestAPIThreatClearIPNoBlocker(t *testing.T) {
	s := newTestServer(t, "tok")
	s.blocker = nil
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", strings.NewReader(`{"ip":"203.0.113.5"}`))
	req.Header.Set("Content-Type", "application/json")
	s.apiThreatClearIP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
	var resp map[string]interface{}
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["status"] != "cleared" {
		t.Errorf("status = %v, want cleared", resp["status"])
	}
}

// apiThreatTempWhitelistIP clamps hours > 168 to 168.
func TestAPIThreatTempWhitelistIPClampsHours(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", strings.NewReader(`{"ip":"203.0.113.5","hours":9999}`))
	req.Header.Set("Content-Type", "application/json")
	s.apiThreatTempWhitelistIP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	var resp map[string]interface{}
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["hours"].(float64) != 168 {
		t.Errorf("hours = %v, want 168 (clamped)", resp["hours"])
	}
}

// apiThreatTempWhitelistIP with hours<=0 defaults to 24.
func TestAPIThreatTempWhitelistIPDefaultsHours(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", strings.NewReader(`{"ip":"203.0.113.5","hours":0}`))
	req.Header.Set("Content-Type", "application/json")
	s.apiThreatTempWhitelistIP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	var resp map[string]interface{}
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["hours"].(float64) != 24 {
		t.Errorf("hours = %v, want 24 (default)", resp["hours"])
	}
}

// apiThreatBulkAction: too many IPs (over 100) returns 400.
func TestAPIThreatBulkActionTooManyIPs(t *testing.T) {
	s := newTestServer(t, "tok")

	var ips []string
	for i := 0; i < 101; i++ {
		ips = append(ips, "203.0.113.5")
	}
	body, _ := json.Marshal(map[string]interface{}{
		"ips":    ips,
		"action": "block",
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	s.apiThreatBulkAction(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("too many IPs = %d, want 400", w.Code)
	}
}

// apiThreatBulkAction: empty IP list returns 400.
func TestAPIThreatBulkActionEmptyIPs(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", strings.NewReader(`{"ips":[],"action":"block"}`))
	req.Header.Set("Content-Type", "application/json")
	s.apiThreatBulkAction(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("empty IPs = %d, want 400", w.Code)
	}
}

// apiThreatBulkAction: unknown action returns 400.
func TestAPIThreatBulkActionUnknownAction(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", strings.NewReader(`{"ips":["203.0.113.5"],"action":"nuke"}`))
	req.Header.Set("Content-Type", "application/json")
	s.apiThreatBulkAction(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("unknown action = %d, want 400", w.Code)
	}
}

// apiThreatBulkAction: whitelist action with valid IPs — exercises whitelist branch.
func TestAPIThreatBulkActionWhitelistValid(t *testing.T) {
	s := newTestServer(t, "tok")
	s.blocker = nil // no blocker — whitelist path still runs threat/attack DB cleanup

	body := `{"ips":["203.0.113.5","198.51.100.1"],"action":"whitelist"}`
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	s.apiThreatBulkAction(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
	var resp map[string]interface{}
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["ok"] != true {
		t.Errorf("ok = %v", resp["ok"])
	}
}

// apiThreatBulkAction: invalid IPs in the list are silently skipped.
func TestAPIThreatBulkActionSkipsInvalidIPs(t *testing.T) {
	s := newTestServer(t, "tok")

	// Two entries — only the valid public IP should be counted.
	body := `{"ips":["not-an-ip","203.0.113.5"],"action":"whitelist"}`
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	s.apiThreatBulkAction(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	var resp map[string]interface{}
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["count"].(float64) != 1 {
		t.Errorf("count = %v, want 1 (invalid IP skipped)", resp["count"])
	}
}

// apiThreatBulkAction: malformed JSON body returns 400.
func TestAPIThreatBulkActionBadJSONBody(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", strings.NewReader(`{not-json`))
	req.Header.Set("Content-Type", "application/json")
	s.apiThreatBulkAction(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("bad JSON = %d, want 400", w.Code)
	}
}
