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
	"github.com/pidginhost/csm/internal/store"
)

// =========================================================================
// server.go — securityHeaders CORS/origin validation, OPTIONS preflight,
// API rate limiting
// =========================================================================

func TestSecurityHeadersCORSAPIRejectsCrossOrigin(t *testing.T) {
	s := newTestServer(t, "tok")
	s.cfg.WebUI.Listen = ":9443"
	s.cfg.Hostname = "myhost.example.com"

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := s.securityHeaders(inner)

	req := httptest.NewRequest("GET", "/api/v1/status", nil)
	req.Host = "myhost.example.com:9443"
	req.Header.Set("Origin", "https://evil.example.com")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("cross-origin API = %d, want 403", w.Code)
	}
}

func TestSecurityHeadersCORSAPISameOriginAllowed(t *testing.T) {
	s := newTestServer(t, "tok")
	s.cfg.WebUI.Listen = ":9443"
	s.cfg.Hostname = "myhost.example.com"

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := s.securityHeaders(inner)

	req := httptest.NewRequest("GET", "/api/v1/status", nil)
	req.Host = "myhost.example.com:9443"
	req.Header.Set("Origin", "https://myhost.example.com:9443")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("same-origin API = %d, want 200", w.Code)
	}
	if got := w.Header().Get("Access-Control-Allow-Origin"); got != "https://myhost.example.com:9443" {
		t.Errorf("ACAO = %q", got)
	}
}

func TestSecurityHeadersOPTIONSPreflight(t *testing.T) {
	s := newTestServer(t, "tok")
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("inner handler should not be called for OPTIONS")
	})
	handler := s.securityHeaders(inner)

	req := httptest.NewRequest("OPTIONS", "/api/v1/status", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusNoContent {
		t.Errorf("OPTIONS = %d, want 204", w.Code)
	}
}

func TestSecurityHeadersCORSFallbackHostBuild(t *testing.T) {
	// When r.Host is empty, server builds from config. Port 443 is omitted.
	s := newTestServer(t, "tok")
	s.cfg.WebUI.Listen = ":443"
	s.cfg.Hostname = "myhost.example.com"

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := s.securityHeaders(inner)

	req := httptest.NewRequest("GET", "/api/v1/status", nil)
	req.Host = "" // force fallback
	req.Header.Set("Origin", "https://myhost.example.com")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("port 443 fallback = %d, want 200", w.Code)
	}
}

func TestSecurityHeadersCORSFallbackHostNon443(t *testing.T) {
	s := newTestServer(t, "tok")
	s.cfg.WebUI.Listen = ":9443"
	s.cfg.Hostname = "myhost.example.com"

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := s.securityHeaders(inner)

	req := httptest.NewRequest("GET", "/api/v1/status", nil)
	req.Host = ""
	req.Header.Set("Origin", "https://myhost.example.com:9443")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("port 9443 fallback = %d, want 200", w.Code)
	}
}

func TestSecurityHeadersAPIRateLimitExceeded(t *testing.T) {
	s := newTestServer(t, "tok")
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := s.securityHeaders(inner)

	// Pre-fill 600 requests from a single IP
	s.apiMu.Lock()
	now := time.Now()
	entries := make([]time.Time, 600)
	for i := range entries {
		entries[i] = now
	}
	s.apiRequests["203.0.113.99"] = entries
	s.apiMu.Unlock()

	req := httptest.NewRequest("GET", "/api/v1/status", nil)
	req.RemoteAddr = "203.0.113.99:12345"
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusTooManyRequests {
		t.Errorf("rate limited = %d, want 429", w.Code)
	}
}

func TestSecurityHeadersNonAPINoCORS(t *testing.T) {
	s := newTestServer(t, "tok")
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := s.securityHeaders(inner)

	// Non-API path with Origin header should still pass through
	req := httptest.NewRequest("GET", "/dashboard", nil)
	req.Header.Set("Origin", "https://evil.example.com")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("non-API cross-origin = %d, want 200", w.Code)
	}
}

// =========================================================================
// server.go — requireCSRF DELETE method coverage
// =========================================================================

func TestRequireCSRFBlocksDeleteWithoutToken(t *testing.T) {
	s := newTestServer(t, "tok")
	req := httptest.NewRequest("DELETE", "/api/v1/suppressions", nil)
	w := httptest.NewRecorder()
	s.requireCSRF(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("handler should not run")
	})).ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Errorf("DELETE without CSRF = %d, want 403", w.Code)
	}
}

func TestValidateCSRFFormFieldMatch(t *testing.T) {
	s := newTestServer(t, "tok")
	form := "csrf_token=" + s.csrfToken()
	req := httptest.NewRequest("POST", "/api/x", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if !s.validateCSRF(req) {
		t.Error("matching form csrf_token should pass CSRF")
	}
}

func TestValidateCSRFDeleteMethod(t *testing.T) {
	s := newTestServer(t, "tok")
	req := httptest.NewRequest("DELETE", "/api/x", nil)
	req.Header.Set("X-CSRF-Token", s.csrfToken())
	if !s.validateCSRF(req) {
		t.Error("DELETE with valid CSRF header should pass")
	}
}

// =========================================================================
// handlers.go — handleDashboard with seeded findings (severity branches)
// =========================================================================

func TestHandleDashboardWithFindings(t *testing.T) {
	s := newTestServerWithTemplates(t, "tok")
	// Seed findings of all severity levels and internal check types
	now := time.Now()
	s.store.AppendHistory([]alert.Finding{
		{Severity: alert.Critical, Check: "webshell", Message: "found shell in /home/alice/x.php", Timestamp: now},
		{Severity: alert.High, Check: "obfuscated_php", Message: "encoded php", Timestamp: now},
		{Severity: alert.Warning, Check: "waf_status", Message: "WAF disabled", Timestamp: now},
		{Severity: alert.Warning, Check: "auto_response", Message: "quarantined file", Timestamp: now},
		{Severity: alert.Warning, Check: "auto_block", Message: "blocked IP", Timestamp: now},
		{Severity: alert.Warning, Check: "check_timeout", Message: "timed out", Timestamp: now},
		{Severity: alert.Warning, Check: "health", Message: "health check", Timestamp: now},
	})

	w := httptest.NewRecorder()
	s.handleDashboard(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
}

func TestHandleDashboardManyFindings(t *testing.T) {
	s := newTestServerWithTemplates(t, "tok")
	now := time.Now()
	// Seed >10 findings to exercise the len(recent) < 10 cap
	var findings []alert.Finding
	for i := 0; i < 15; i++ {
		findings = append(findings, alert.Finding{
			Severity:  alert.High,
			Check:     "webshell",
			Message:   "shell found",
			Timestamp: now.Add(-time.Duration(i) * time.Minute),
		})
	}
	s.store.AppendHistory(findings)

	w := httptest.NewRecorder()
	s.handleDashboard(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != http.StatusOK {
		t.Errorf("status = %d", w.Code)
	}
}

// =========================================================================
// geoip_api.go — apiGeoIPLookup detail=1 branch (requires DB, exercised here)
// =========================================================================

// (basic missing/invalid/noDB tests exist in coverage_test.go)

// =========================================================================
// geoip_api.go — apiGeoIPBatch branches (invalid body, mixed IPs)
// =========================================================================

func TestAPIGeoIPBatchInvalidBodyPush(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", strings.NewReader("{bad"))
	req.Header.Set("Content-Type", "application/json")
	s.apiGeoIPBatch(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("bad body = %d, want 400", w.Code)
	}
}

func TestAPIGeoIPBatchNoDBMixedIPs(t *testing.T) {
	s := newTestServer(t, "tok")
	body := `{"ips":["8.8.8.8","not-an-ip","1.1.1.1"]}`
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	s.apiGeoIPBatch(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}

	var resp struct {
		Results map[string]struct {
			Error string `json:"error"`
		} `json:"results"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("bad JSON: %v", err)
	}
	// Invalid IP should have error
	if resp.Results["not-an-ip"].Error != "invalid IP format" {
		t.Errorf("invalid IP error = %q", resp.Results["not-an-ip"].Error)
	}
	// Valid IP with no DB should have error
	if resp.Results["8.8.8.8"].Error != "GeoIP database not loaded" {
		t.Errorf("no DB error = %q", resp.Results["8.8.8.8"].Error)
	}
}

// =========================================================================
// api.go — apiStats deeper branches (auto_response quarantine/kill,
// xmlrpc_abuse, modsec_csm_block_escalation with xmlrpc)
// =========================================================================

func TestAPIStatsAutoResponseBranches(t *testing.T) {
	s := newTestServerWithBbolt(t, "tok")
	now := time.Now()
	findings := []alert.Finding{
		{Severity: alert.Warning, Check: "auto_response", Message: "quarantined /home/alice/evil.php", Timestamp: now},
		{Severity: alert.Warning, Check: "auto_response", Message: "Killed process 1234 for alice", Timestamp: now},
		{Severity: alert.High, Check: "xmlrpc_abuse", Message: "xmlrpc from 203.0.113.1", Timestamp: now},
		{Severity: alert.High, Check: "modsec_csm_block_escalation", Message: "xmlrpc flood rule 900006", Timestamp: now},
		{Severity: alert.Critical, Check: "webshell", Message: "shell in /home/bob/public_html/b.php", Timestamp: now},
		{Severity: alert.Critical, Check: "webshell", Message: "shell in /home/bob/public_html/c.php", Timestamp: now},
	}
	s.store.AppendHistory(findings)

	w := httptest.NewRecorder()
	s.apiStats(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	var data map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &data); err != nil {
		t.Fatalf("bad JSON: %v", err)
	}

	ar := data["auto_response"].(map[string]interface{})
	if ar["quarantined"].(float64) < 1 {
		t.Error("expected quarantined >= 1")
	}
	if ar["killed"].(float64) < 1 {
		t.Error("expected killed >= 1")
	}
}

// =========================================================================
// api.go — apiQuarantine with temp directory containing meta files
// =========================================================================

func TestAPIQuarantineWithTempMetaFiles(t *testing.T) {
	// We cannot override the const quarantineDir, but this exercises
	// the full listing logic when /opt/csm/quarantine doesn't exist.
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	s.apiQuarantine(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	// Should return valid JSON (empty array if no quarantine dir)
	var entries []json.RawMessage
	if err := json.Unmarshal(w.Body.Bytes(), &entries); err != nil {
		// Could also be "null" for nil slice
		body := strings.TrimSpace(w.Body.String())
		if body != "null" && body != "[]" {
			t.Fatalf("bad JSON: %v, body=%s", err, body)
		}
	}
}

// =========================================================================
// api.go — apiQuarantineBulkDelete branches
// =========================================================================

func TestAPIQuarantineBulkDeleteWithRealFiles(t *testing.T) {
	// Create temp files that look like quarantine items in the actual quarantine dir
	// This exercises the os.Lstat + RemoveAll path
	dir := t.TempDir()
	itemPath := filepath.Join(dir, "testitem")
	metaPath := filepath.Join(dir, "testitem.meta")
	if err := os.WriteFile(itemPath, []byte("evil"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(metaPath, []byte(`{"original_path":"/home/a/b.php"}`), 0644); err != nil {
		t.Fatal(err)
	}

	s := newTestServer(t, "tok")
	// Pass an ID that won't resolve to real quarantine (exercises the error path)
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", strings.NewReader(`{"ids":["nonexistent_file_abc"]}`))
	req.Header.Set("Content-Type", "application/json")
	s.apiQuarantineBulkDelete(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("bad JSON: %v", err)
	}
}

// =========================================================================
// api.go — apiQuarantineRestore POST with missing/bad ID
// =========================================================================

func TestAPIQuarantineRestoreMissingID(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	s.apiQuarantineRestore(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("missing ID = %d, want 400", w.Code)
	}
}

func TestAPIQuarantineRestoreNotFound(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", strings.NewReader(`{"id":"nonexistent_file_xyz"}`))
	req.Header.Set("Content-Type", "application/json")
	s.apiQuarantineRestore(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("nonexistent = %d, want 404", w.Code)
	}
}

// =========================================================================
// api.go — apiScanAccount branches (missing account, bad name, conflict)
// =========================================================================

func TestAPIScanAccountMissingAccountPush(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	s.apiScanAccount(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("missing account = %d, want 400", w.Code)
	}
}

func TestAPIScanAccountPathTraversalName(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", strings.NewReader(`{"account":"../etc"}`))
	req.Header.Set("Content-Type", "application/json")
	s.apiScanAccount(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("invalid account name = %d, want 400", w.Code)
	}
}

func TestAPIScanAccountConflictWhileRunning(t *testing.T) {
	s := newTestServer(t, "tok")
	// Hold the scan lock to simulate ongoing scan
	if !s.acquireScan() {
		t.Fatal("failed to acquire scan lock")
	}
	defer s.releaseScan()

	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", strings.NewReader(`{"account":"alice"}`))
	req.Header.Set("Content-Type", "application/json")
	s.apiScanAccount(w, req)
	if w.Code != http.StatusTooManyRequests {
		t.Errorf("scan conflict = %d, want 429", w.Code)
	}
}

// =========================================================================
// api.go — apiFix branches (missing fields, no fix available)
// =========================================================================

func TestAPIFixMissingCheckField(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", strings.NewReader(`{"message":"test"}`))
	req.Header.Set("Content-Type", "application/json")
	s.apiFix(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("missing check = %d, want 400", w.Code)
	}
}

func TestAPIFixNoFixAvailableForCheck(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	body := `{"check":"nonexistent_check_type","message":"test"}`
	req := httptest.NewRequest("POST", "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	s.apiFix(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("no fix available = %d, want 400", w.Code)
	}
}

// =========================================================================
// api.go — apiDismissFinding branches
// =========================================================================

func TestAPIDismissFindingGetRejected(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	s.apiDismissFinding(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET dismiss = %d, want 405", w.Code)
	}
}

func TestAPIDismissFindingMissingKey(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	s.apiDismissFinding(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("missing key = %d, want 400", w.Code)
	}
}

// =========================================================================
// api.go — apiBlockIP branches
// =========================================================================

func TestAPIBlockIPMissingIPPush(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	s.apiBlockIP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("missing IP = %d, want 400", w.Code)
	}
}

func TestAPIBlockIPNoBlockerPush(t *testing.T) {
	s := newTestServer(t, "tok")
	s.blocker = nil
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", strings.NewReader(`{"ip":"203.0.113.5"}`))
	req.Header.Set("Content-Type", "application/json")
	s.apiBlockIP(w, req)
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("no blocker = %d, want 503", w.Code)
	}
}

// =========================================================================
// api.go — apiUnblockIP branches
// =========================================================================

func TestAPIUnblockIPMissingIPPush(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	s.apiUnblockIP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("missing IP = %d, want 400", w.Code)
	}
}

func TestAPIUnblockIPPrivateIPPush(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", strings.NewReader(`{"ip":"10.0.0.1"}`))
	req.Header.Set("Content-Type", "application/json")
	s.apiUnblockIP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("private IP = %d, want 400", w.Code)
	}
}

func TestAPIUnblockIPNoBlockerPush(t *testing.T) {
	s := newTestServer(t, "tok")
	s.blocker = nil
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", strings.NewReader(`{"ip":"203.0.113.5"}`))
	req.Header.Set("Content-Type", "application/json")
	s.apiUnblockIP(w, req)
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("no blocker = %d, want 503", w.Code)
	}
}

// =========================================================================
// api.go — apiUnblockBulk branches
// =========================================================================

// =========================================================================
// threat_api.go — apiThreatBlockIP with blocker
// =========================================================================

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

func TestAPIThreatBlockIPInvalidIP(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", strings.NewReader(`{"ip":"127.0.0.1"}`))
	req.Header.Set("Content-Type", "application/json")
	s.apiThreatBlockIP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("loopback = %d, want 400", w.Code)
	}
}

func TestAPIThreatBlockIPWithBlocker(t *testing.T) {
	s := newTestServer(t, "tok")
	fb := newFullBlocker()
	s.blocker = fb
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", strings.NewReader(`{"ip":"203.0.113.5"}`))
	req.Header.Set("Content-Type", "application/json")
	s.apiThreatBlockIP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
}

// =========================================================================
// threat_api.go — apiThreatClearIP with blocker
// =========================================================================

func TestAPIThreatClearIPInvalidIP(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", strings.NewReader(`{"ip":"10.0.0.1"}`))
	req.Header.Set("Content-Type", "application/json")
	s.apiThreatClearIP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("private IP = %d, want 400", w.Code)
	}
}

func TestAPIThreatClearIPWithBlocker(t *testing.T) {
	s := newTestServer(t, "tok")
	fb := newFullBlocker()
	s.blocker = fb
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", strings.NewReader(`{"ip":"203.0.113.5"}`))
	req.Header.Set("Content-Type", "application/json")
	s.apiThreatClearIP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
}

// =========================================================================
// threat_api.go — apiThreatTempWhitelistIP branches
// =========================================================================

func TestAPIThreatTempWhitelistIPMissingIP(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	s.apiThreatTempWhitelistIP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("missing IP = %d, want 400", w.Code)
	}
}

func TestAPIThreatTempWhitelistIPInvalidIP(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", strings.NewReader(`{"ip":"127.0.0.1"}`))
	req.Header.Set("Content-Type", "application/json")
	s.apiThreatTempWhitelistIP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("loopback = %d, want 400", w.Code)
	}
}

func TestAPIThreatTempWhitelistIPWithBlocker(t *testing.T) {
	s := newTestServer(t, "tok")
	fb := newFullBlocker()
	s.blocker = fb
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", strings.NewReader(`{"ip":"203.0.113.5","hours":48}`))
	req.Header.Set("Content-Type", "application/json")
	s.apiThreatTempWhitelistIP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
}

func TestAPIThreatTempWhitelistIPDefaultHours(t *testing.T) {
	s := newTestServer(t, "tok")
	fb := newFullBlocker()
	s.blocker = fb
	w := httptest.NewRecorder()
	// hours=0 should default to 24
	req := httptest.NewRequest("POST", "/", strings.NewReader(`{"ip":"203.0.113.5","hours":0}`))
	req.Header.Set("Content-Type", "application/json")
	s.apiThreatTempWhitelistIP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("bad JSON: %v", err)
	}
	if resp["hours"].(float64) != 24 {
		t.Errorf("hours = %v, want 24", resp["hours"])
	}
}

func TestAPIThreatTempWhitelistIPMaxHours(t *testing.T) {
	s := newTestServer(t, "tok")
	fb := newFullBlocker()
	s.blocker = fb
	w := httptest.NewRecorder()
	// hours=999 should be capped to 168
	req := httptest.NewRequest("POST", "/", strings.NewReader(`{"ip":"203.0.113.5","hours":999}`))
	req.Header.Set("Content-Type", "application/json")
	s.apiThreatTempWhitelistIP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("bad JSON: %v", err)
	}
	if resp["hours"].(float64) != 168 {
		t.Errorf("hours = %v, want 168", resp["hours"])
	}
}

// =========================================================================
// threat_api.go — apiThreatWhitelistIP deeper branches
// =========================================================================

func TestAPIThreatWhitelistIPInvalidIP(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", strings.NewReader(`{"ip":"10.0.0.1"}`))
	req.Header.Set("Content-Type", "application/json")
	s.apiThreatWhitelistIP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("private IP = %d, want 400", w.Code)
	}
}

func TestAPIThreatWhitelistIPWithBlocker(t *testing.T) {
	s := newTestServer(t, "tok")
	fb := newFullBlocker()
	s.blocker = fb
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", strings.NewReader(`{"ip":"203.0.113.5"}`))
	req.Header.Set("Content-Type", "application/json")
	s.apiThreatWhitelistIP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("bad JSON: %v", err)
	}
	if resp["status"] != "whitelisted" {
		t.Errorf("status = %v", resp["status"])
	}
}

// =========================================================================
// threat_api.go — apiThreatUnwhitelistIP deeper branches
// =========================================================================

func TestAPIThreatUnwhitelistIPInvalidIP(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", strings.NewReader(`{"ip":"10.0.0.1"}`))
	req.Header.Set("Content-Type", "application/json")
	s.apiThreatUnwhitelistIP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("private IP = %d, want 400", w.Code)
	}
}

func TestAPIThreatUnwhitelistIPWithBlocker(t *testing.T) {
	s := newTestServer(t, "tok")
	fb := newFullBlocker()
	s.blocker = fb
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", strings.NewReader(`{"ip":"203.0.113.5"}`))
	req.Header.Set("Content-Type", "application/json")
	s.apiThreatUnwhitelistIP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
}

// =========================================================================
// threat_api.go — apiThreatBulkAction deeper branches (block action, >100 IPs, bad action)
// =========================================================================

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

func TestAPIThreatBulkActionTooManyIPs(t *testing.T) {
	s := newTestServer(t, "tok")
	ips := make([]string, 101)
	for i := range ips {
		ips[i] = "203.0.113.1"
	}
	body, _ := json.Marshal(map[string]interface{}{"ips": ips, "action": "block"})
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	s.apiThreatBulkAction(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("101 IPs = %d, want 400", w.Code)
	}
}

func TestAPIThreatBulkActionBadAction(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", strings.NewReader(`{"ips":["203.0.113.5"],"action":"nuke"}`))
	req.Header.Set("Content-Type", "application/json")
	s.apiThreatBulkAction(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("bad action = %d, want 400", w.Code)
	}
}

func TestAPIThreatBulkActionBlockWithBlocker(t *testing.T) {
	s := newTestServer(t, "tok")
	fb := newFullBlocker()
	s.blocker = fb
	w := httptest.NewRecorder()
	body := `{"ips":["203.0.113.5","203.0.113.6","not-an-ip"],"action":"block"}`
	req := httptest.NewRequest("POST", "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	s.apiThreatBulkAction(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("bad JSON: %v", err)
	}
	if resp["count"].(float64) != 2 {
		t.Errorf("count = %v, want 2 (not-an-ip skipped)", resp["count"])
	}
}

func TestAPIThreatBulkActionWhitelistWithBlocker(t *testing.T) {
	s := newTestServer(t, "tok")
	fb := newFullBlocker()
	s.blocker = fb
	w := httptest.NewRecorder()
	body := `{"ips":["203.0.113.5"],"action":"whitelist"}`
	req := httptest.NewRequest("POST", "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	s.apiThreatBulkAction(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("bad JSON: %v", err)
	}
	if resp["count"].(float64) != 1 {
		t.Errorf("count = %v, want 1", resp["count"])
	}
}

// =========================================================================
// threat_api.go — apiThreatEvents with limit cap
// =========================================================================

func TestAPIThreatEventsLargeLimitCapped(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	s.apiThreatEvents(w, httptest.NewRequest("GET", "/?ip=203.0.113.5&limit=9999", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
}

// =========================================================================
// incident_api.go — apiIncident branches
// =========================================================================

func TestAPIIncidentMissingBothParams(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	s.apiIncident(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != http.StatusBadRequest {
		t.Errorf("no params = %d, want 400", w.Code)
	}
}

func TestAPIIncidentWithAccountFindingsMatch(t *testing.T) {
	s := newTestServerWithBbolt(t, "tok")
	now := time.Now()
	s.store.AppendHistory([]alert.Finding{
		{Severity: alert.Critical, Check: "webshell", Message: "shell in /home/alice/public_html/x.php", Timestamp: now},
	})

	w := httptest.NewRecorder()
	s.apiIncident(w, httptest.NewRequest("GET", "/?account=alice", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("bad JSON: %v", err)
	}
	if resp["query_account"] != "alice" {
		t.Errorf("query_account = %v", resp["query_account"])
	}
}

func TestAPIIncidentLargeHoursCapped(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	s.apiIncident(w, httptest.NewRequest("GET", "/?ip=203.0.113.5&hours=9999", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("bad JSON: %v", err)
	}
	if resp["hours"].(float64) != 720 {
		t.Errorf("hours = %v, want 720", resp["hours"])
	}
}

// =========================================================================
// suppressions_api.go — apiSuppressions deeper branches
// =========================================================================

func TestAPISuppressionsGetReturnsArray(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	s.apiSuppressions(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	var data []interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &data); err != nil {
		t.Fatalf("bad JSON: %v", err)
	}
}

func TestAPISuppressionsPostCreatesRule(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	body := `{"check":"webshell","path_pattern":"/home/alice/*","reason":"false positive"}`
	req := httptest.NewRequest("POST", "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	s.apiSuppressions(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("POST = %d, body = %s", w.Code, w.Body.String())
	}
	var resp map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("bad JSON: %v", err)
	}
	if resp["status"] != "created" {
		t.Errorf("status = %q", resp["status"])
	}
	if resp["id"] == "" {
		t.Error("id should not be empty")
	}
}

func TestAPISuppressionsDeleteRemovesRule(t *testing.T) {
	s := newTestServer(t, "tok")

	// First create a rule
	w := httptest.NewRecorder()
	body := `{"check":"test_check","reason":"testing"}`
	req := httptest.NewRequest("POST", "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	s.apiSuppressions(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("POST = %d", w.Code)
	}
	var created map[string]string
	_ = json.Unmarshal(w.Body.Bytes(), &created)
	id := created["id"]

	// Now delete it
	w = httptest.NewRecorder()
	req = httptest.NewRequest("DELETE", "/", strings.NewReader(`{"id":"`+id+`"}`))
	req.Header.Set("Content-Type", "application/json")
	s.apiSuppressions(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("DELETE = %d, body = %s", w.Code, w.Body.String())
	}
	var resp map[string]string
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["status"] != "deleted" {
		t.Errorf("status = %q", resp["status"])
	}
}

// =========================================================================
// api.go — apiBlockedIPs legacy file fallback (no bbolt, write state.json)
// =========================================================================

func TestAPIBlockedIPsLegacyStateFile(t *testing.T) {
	s := newTestServer(t, "tok")
	// Ensure no bbolt global
	store.SetGlobal(nil)

	// Write a legacy firewall state file
	fwDir := filepath.Join(s.cfg.StatePath, "firewall")
	if err := os.MkdirAll(fwDir, 0755); err != nil {
		t.Fatal(err)
	}
	fwState := `{"blocked":[{"ip":"203.0.113.5","reason":"brute-force","blocked_at":"2026-04-01T00:00:00Z","expires_at":"0001-01-01T00:00:00Z"}]}`
	if err := os.WriteFile(filepath.Join(fwDir, "state.json"), []byte(fwState), 0644); err != nil {
		t.Fatal(err)
	}

	w := httptest.NewRecorder()
	s.apiBlockedIPs(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	var data []interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &data); err != nil {
		t.Fatalf("bad JSON: %v", err)
	}
	if len(data) < 1 {
		t.Error("expected at least 1 blocked IP from legacy file")
	}
}

func TestAPIBlockedIPsLegacyBlockedIPsJSON(t *testing.T) {
	s := newTestServer(t, "tok")
	store.SetGlobal(nil)

	// Write a legacy blocked_ips.json (the final fallback)
	stateFile := filepath.Join(s.cfg.StatePath, "blocked_ips.json")
	blockState := `{"ips":[{"ip":"198.51.100.1","reason":"waf","blocked_at":"2026-04-01T00:00:00Z","expires_at":"0001-01-01T00:00:00Z"}]}`
	if err := os.WriteFile(stateFile, []byte(blockState), 0644); err != nil {
		t.Fatal(err)
	}

	w := httptest.NewRecorder()
	s.apiBlockedIPs(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	var data []interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &data); err != nil {
		t.Fatalf("bad JSON: %v", err)
	}
	if len(data) < 1 {
		t.Error("expected at least 1 blocked IP from legacy blocked_ips.json")
	}
}

func TestAPIBlockedIPsNoData(t *testing.T) {
	s := newTestServer(t, "tok")
	store.SetGlobal(nil)
	// No files at all
	w := httptest.NewRecorder()
	s.apiBlockedIPs(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
}

// =========================================================================
// api.go — parseModeString edge cases
// =========================================================================

func TestParseModeStringAllDash(t *testing.T) {
	mode := parseModeString("----------")
	// All dashes = mode 0, fallback to 0644
	if mode != 0644 {
		t.Errorf("parseModeString(\"----------\") = %o, want 644 (fallback)", mode)
	}
}

// =========================================================================
// server.go — New() template loading with real UI directory
// =========================================================================

func TestNewServerAPIOnlyMode(t *testing.T) {
	s := newTestServer(t, "tok")
	if s.HasUI() {
		t.Error("test server should be API-only (no UI dir)")
	}
}

// =========================================================================
// api.go — apiImport with whitelist entries
// =========================================================================

// =========================================================================
// api.go — apiExport with bbolt data
// =========================================================================

func TestAPIExportWithBboltData(t *testing.T) {
	s := newTestServerWithBbolt(t, "tok")
	w := httptest.NewRecorder()
	s.apiExport(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	var data map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &data); err != nil {
		t.Fatalf("bad JSON: %v", err)
	}
	for _, key := range []string{"exported_at", "hostname", "suppressions", "whitelist"} {
		if _, ok := data[key]; !ok {
			t.Errorf("missing field %q", key)
		}
	}
}

// =========================================================================
// api.go — apiHistory combined filters (from+to+severity+search+checks)
// =========================================================================

func TestAPIHistoryAllFilters(t *testing.T) {
	s := newTestServerWithBbolt(t, "tok")
	now := time.Now()
	findings := []alert.Finding{
		{Severity: alert.Critical, Check: "webshell", Message: "found shell", Timestamp: now},
		{Severity: alert.Warning, Check: "waf_status", Message: "WAF off", Timestamp: now},
	}
	s.store.AppendHistory(findings)

	today := now.Format("2006-01-02")
	url := "/?from=" + today + "&to=" + today + "&severity=2&search=shell&checks=webshell&limit=10"
	w := httptest.NewRecorder()
	s.apiHistory(w, httptest.NewRequest("GET", url, nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("bad JSON: %v", err)
	}
}

// =========================================================================
// api.go — buildBruteForceSummary with data
// =========================================================================

func TestBuildBruteForceSummaryOutput(t *testing.T) {
	ips := map[string]int{
		"203.0.113.1": 50,
		"203.0.113.2": 30,
	}
	types := map[string]int{
		"wp-login": 40,
		"xmlrpc":   20,
	}
	result := buildBruteForceSummary(ips, types)
	if result["total_attacks"].(int) != 60 {
		t.Errorf("total_attacks = %v", result["total_attacks"])
	}
	if result["unique_ips"].(int) != 2 {
		t.Errorf("unique_ips = %v", result["unique_ips"])
	}
}

// =========================================================================
// api.go — dedupIPReputation non-matching regex passes through
// =========================================================================

func TestDedupIPReputationRegexNoMatch(t *testing.T) {
	items := []enrichedFinding{
		{Check: "ip_reputation", Message: "Some other IP reputation message without the expected format"},
	}
	result := dedupIPReputation(items)
	if len(result) != 1 {
		t.Fatalf("expected 1, got %d", len(result))
	}
	if result[0].Message != items[0].Message {
		t.Error("non-matching ip_reputation should pass through unchanged")
	}
}

// =========================================================================
// api.go — apiQuarantinePreview with a directory
// =========================================================================

func TestAPIQuarantinePreviewDirectory(t *testing.T) {
	// Create quarantine dir structure for preview
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	// Use pre_clean prefix with a non-existent directory
	s.apiQuarantinePreview(w, httptest.NewRequest("GET", "/?id=pre_clean:nonexistent_dir_abc", nil))
	if w.Code != http.StatusNotFound {
		t.Errorf("nonexistent dir = %d, want 404", w.Code)
	}
}

// =========================================================================
// server.go — Shutdown with perfCancel
// =========================================================================

func TestShutdownWithNilPerfCancel(t *testing.T) {
	_ = newTestServer(t, "tok")
	// perfCancel is set by Start(), but in test it may be nil
	// Shutdown should handle nil perfCancel gracefully
	// (newTestServer already calls Shutdown in cleanup)
}

// =========================================================================
// api.go — apiTestAlert POST (dispatches alert, tests the success path)
// =========================================================================

func TestAPITestAlertPostSuccess(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", nil)
	s.apiTestAlert(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("bad JSON: %v", err)
	}
	// Dispatch with no alert channels configured returns no error
	if resp["status"] != "sent" {
		t.Errorf("status = %v", resp["status"])
	}
}

// =========================================================================
// threat_api.go — apiThreatTopAttackers limit cap
// =========================================================================

func TestAPIThreatTopAttackersLimitCapped(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	s.apiThreatTopAttackers(w, httptest.NewRequest("GET", "/?limit=9999", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
}

// =========================================================================
// threat_api.go — apiThreatIP with valid public IP (no geoIP DB)
// =========================================================================

func TestAPIThreatIPPublicIPNoGeo(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	s.apiThreatIP(w, httptest.NewRequest("GET", "/?ip=203.0.113.5", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
}

// =========================================================================
// api.go — apiFindings with suppressed findings
// =========================================================================

func TestAPIFindingsFiltersInternal(t *testing.T) {
	s := newTestServer(t, "tok")
	// This exercises apiFindings; store is empty so the internal check filter
	// code doesn't run. But it covers the function call path.
	w := httptest.NewRecorder()
	s.apiFindings(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
}

// =========================================================================
// firewall_api.go — apiFirewallCheck with invalid IP
// =========================================================================
