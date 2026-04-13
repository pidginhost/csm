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
// server.go — securityHeaders CORS/origin validation, OPTIONS, rate limit
// =========================================================================

func TestSecurityHeadersCORSRejectsCrossOriginAPI(t *testing.T) {
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

func TestSecurityHeadersCORSSameOriginPassesAPI(t *testing.T) {
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

func TestSecurityHeadersOPTIONSReturns204(t *testing.T) {
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

func TestSecurityHeadersCORSFallbackPort443(t *testing.T) {
	s := newTestServer(t, "tok")
	s.cfg.WebUI.Listen = ":443"
	s.cfg.Hostname = "myhost.example.com"

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := s.securityHeaders(inner)

	req := httptest.NewRequest("GET", "/api/v1/status", nil)
	req.Host = ""
	req.Header.Set("Origin", "https://myhost.example.com")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("port 443 fallback = %d, want 200", w.Code)
	}
}

func TestSecurityHeadersCORSFallbackNon443Port(t *testing.T) {
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

func TestSecurityHeadersAPIRateLimitHit(t *testing.T) {
	s := newTestServer(t, "tok")
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := s.securityHeaders(inner)

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

func TestSecurityHeadersNonAPIIgnoresOrigin(t *testing.T) {
	s := newTestServer(t, "tok")
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := s.securityHeaders(inner)

	req := httptest.NewRequest("GET", "/dashboard", nil)
	req.Header.Set("Origin", "https://evil.example.com")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("non-API cross-origin = %d, want 200", w.Code)
	}
}

// =========================================================================
// server.go — requireCSRF DELETE coverage, form field CSRF
// =========================================================================

func TestRequireCSRFRejectsDeleteNoToken(t *testing.T) {
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

func TestValidateCSRFViaFormField(t *testing.T) {
	s := newTestServer(t, "tok")
	form := "csrf_token=" + s.csrfToken()
	req := httptest.NewRequest("POST", "/api/x", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if !s.validateCSRF(req) {
		t.Error("matching form csrf_token should pass CSRF")
	}
}

func TestValidateCSRFOnDeleteWithHeader(t *testing.T) {
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

func TestHandleDashboardSeverityBranches(t *testing.T) {
	s := newTestServerWithTemplates(t, "tok")
	now := time.Now()
	s.store.AppendHistory([]alert.Finding{
		{Severity: alert.Critical, Check: "webshell", Message: "found shell", Timestamp: now},
		{Severity: alert.High, Check: "obfuscated_php", Message: "encoded", Timestamp: now},
		{Severity: alert.Warning, Check: "waf_status", Message: "WAF off", Timestamp: now},
		{Severity: alert.Warning, Check: "auto_response", Message: "quarantined", Timestamp: now},
		{Severity: alert.Warning, Check: "auto_block", Message: "blocked", Timestamp: now},
		{Severity: alert.Warning, Check: "check_timeout", Message: "timed out", Timestamp: now},
		{Severity: alert.Warning, Check: "health", Message: "health check", Timestamp: now},
	})

	w := httptest.NewRecorder()
	s.handleDashboard(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
}

func TestHandleDashboardRecentCapped(t *testing.T) {
	s := newTestServerWithTemplates(t, "tok")
	now := time.Now()
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
// geoip_api.go — apiGeoIPBatch (invalid body, mixed valid/invalid/no-DB)
// =========================================================================

func TestAPIGeoIPBatchMalformedJSON(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", strings.NewReader("{bad"))
	req.Header.Set("Content-Type", "application/json")
	s.apiGeoIPBatch(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("bad body = %d, want 400", w.Code)
	}
}

func TestAPIGeoIPBatchMixedIPsNoDatabase(t *testing.T) {
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
	if resp.Results["not-an-ip"].Error != "invalid IP format" {
		t.Errorf("invalid IP error = %q", resp.Results["not-an-ip"].Error)
	}
	if resp.Results["8.8.8.8"].Error != "GeoIP database not loaded" {
		t.Errorf("no DB error = %q", resp.Results["8.8.8.8"].Error)
	}
}

// =========================================================================
// api.go — apiStats auto_response branches (quarantine/kill/xmlrpc/modsec)
// =========================================================================

func TestAPIStatsAutoResponseQuarantineKill(t *testing.T) {
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
// api.go — apiQuarantineRestore POST branches
// =========================================================================

func TestAPIQuarantineRestoreEmptyID(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	s.apiQuarantineRestore(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("empty ID = %d, want 400", w.Code)
	}
}

func TestAPIQuarantineRestoreTraversalID(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", strings.NewReader(`{"id":".."}`))
	req.Header.Set("Content-Type", "application/json")
	s.apiQuarantineRestore(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf(".. ID = %d, want 400", w.Code)
	}
}

func TestAPIQuarantineRestoreNonexistentMeta(t *testing.T) {
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
// api.go — apiScanAccount branches
// =========================================================================

func TestAPIScanAccountEmptyBody(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	s.apiScanAccount(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("empty body = %d, want 400", w.Code)
	}
}

func TestAPIScanAccountPathTraversal(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", strings.NewReader(`{"account":"../etc"}`))
	req.Header.Set("Content-Type", "application/json")
	s.apiScanAccount(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("traversal = %d, want 400", w.Code)
	}
}

func TestAPIScanAccountLockConflict(t *testing.T) {
	s := newTestServer(t, "tok")
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
// api.go — apiFix branches
// =========================================================================

func TestAPIFixEmptyCheck(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", strings.NewReader(`{"message":"test"}`))
	req.Header.Set("Content-Type", "application/json")
	s.apiFix(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("missing check = %d, want 400", w.Code)
	}
}

func TestAPIFixUnknownCheck(t *testing.T) {
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

func TestAPIDismissFindingMethodGuard(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	s.apiDismissFinding(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET dismiss = %d, want 405", w.Code)
	}
}

func TestAPIDismissFindingEmptyKeyField(t *testing.T) {
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
// api.go — apiBlockIP deeper branches
// =========================================================================

func TestAPIBlockIPEmptyIPField(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	s.apiBlockIP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("missing IP = %d, want 400", w.Code)
	}
}

func TestAPIBlockIPBlockerUnavailable(t *testing.T) {
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

func TestAPIBlockIPWithCustomReason(t *testing.T) {
	s := newTestServer(t, "tok")
	fb := newFullBlocker()
	s.blocker = fb
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", strings.NewReader(`{"ip":"203.0.113.5","reason":"custom reason"}`))
	req.Header.Set("Content-Type", "application/json")
	s.apiBlockIP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	if fb.blocked["203.0.113.5"] != "custom reason" {
		t.Errorf("reason = %q", fb.blocked["203.0.113.5"])
	}
}

// =========================================================================
// api.go — apiUnblockIP deeper branches
// =========================================================================

func TestAPIUnblockIPEmptyIP(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	s.apiUnblockIP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("missing IP = %d, want 400", w.Code)
	}
}

func TestAPIUnblockIPBlockerUnavailable(t *testing.T) {
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
// threat_api.go — apiThreatBlockIP with blocker
// =========================================================================

func TestAPIThreatBlockIPBlockerUnavailable(t *testing.T) {
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

func TestAPIThreatBlockIPLoopback(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", strings.NewReader(`{"ip":"127.0.0.1"}`))
	req.Header.Set("Content-Type", "application/json")
	s.apiThreatBlockIP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("loopback = %d, want 400", w.Code)
	}
}

func TestAPIThreatBlockIPSuccessWithBlocker(t *testing.T) {
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

func TestAPIThreatClearIPPrivateIP(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", strings.NewReader(`{"ip":"10.0.0.1"}`))
	req.Header.Set("Content-Type", "application/json")
	s.apiThreatClearIP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("private IP = %d, want 400", w.Code)
	}
}

func TestAPIThreatClearIPSuccessWithBlocker(t *testing.T) {
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

func TestAPIThreatTempWhitelistIPEmptyBody(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	s.apiThreatTempWhitelistIP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("missing IP = %d, want 400", w.Code)
	}
}

func TestAPIThreatTempWhitelistIPLoopback(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", strings.NewReader(`{"ip":"127.0.0.1"}`))
	req.Header.Set("Content-Type", "application/json")
	s.apiThreatTempWhitelistIP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("loopback = %d, want 400", w.Code)
	}
}

func TestAPIThreatTempWhitelistIPSuccessWithBlocker(t *testing.T) {
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

func TestAPIThreatTempWhitelistIPDefaultsTo24h(t *testing.T) {
	s := newTestServer(t, "tok")
	fb := newFullBlocker()
	s.blocker = fb
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
		t.Errorf("hours = %v, want 24", resp["hours"])
	}
}

func TestAPIThreatTempWhitelistIPCapsTo168h(t *testing.T) {
	s := newTestServer(t, "tok")
	fb := newFullBlocker()
	s.blocker = fb
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", strings.NewReader(`{"ip":"203.0.113.5","hours":999}`))
	req.Header.Set("Content-Type", "application/json")
	s.apiThreatTempWhitelistIP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	var resp map[string]interface{}
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["hours"].(float64) != 168 {
		t.Errorf("hours = %v, want 168", resp["hours"])
	}
}

// =========================================================================
// threat_api.go — apiThreatWhitelistIP with blocker
// =========================================================================

func TestAPIThreatWhitelistIPPrivateIPRejected(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", strings.NewReader(`{"ip":"10.0.0.1"}`))
	req.Header.Set("Content-Type", "application/json")
	s.apiThreatWhitelistIP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("private IP = %d, want 400", w.Code)
	}
}

func TestAPIThreatWhitelistIPSuccessWithBlocker(t *testing.T) {
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
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["status"] != "whitelisted" {
		t.Errorf("status = %v", resp["status"])
	}
}

// =========================================================================
// threat_api.go — apiThreatUnwhitelistIP with blocker
// =========================================================================

func TestAPIThreatUnwhitelistIPPrivateIPRejected(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", strings.NewReader(`{"ip":"10.0.0.1"}`))
	req.Header.Set("Content-Type", "application/json")
	s.apiThreatUnwhitelistIP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("private IP = %d, want 400", w.Code)
	}
}

func TestAPIThreatUnwhitelistIPSuccessWithBlocker(t *testing.T) {
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
// threat_api.go — apiThreatBulkAction deeper branches
// =========================================================================

func TestAPIThreatBulkActionZeroIPs(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", strings.NewReader(`{"ips":[],"action":"block"}`))
	req.Header.Set("Content-Type", "application/json")
	s.apiThreatBulkAction(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("empty IPs = %d, want 400", w.Code)
	}
}

func TestAPIThreatBulkAction101IPs(t *testing.T) {
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

func TestAPIThreatBulkActionInvalidAction(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", strings.NewReader(`{"ips":["203.0.113.5"],"action":"nuke"}`))
	req.Header.Set("Content-Type", "application/json")
	s.apiThreatBulkAction(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("bad action = %d, want 400", w.Code)
	}
}

func TestAPIThreatBulkActionBlockSkipsInvalid(t *testing.T) {
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
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["count"].(float64) != 2 {
		t.Errorf("count = %v, want 2", resp["count"])
	}
}

func TestAPIThreatBulkActionWhitelistWithFullBlocker(t *testing.T) {
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
}

// =========================================================================
// threat_api.go — apiThreatEvents limit cap
// =========================================================================

func TestAPIThreatEventsLimitCappedAt500(t *testing.T) {
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

func TestAPIIncidentRequiresIPOrAccount(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	s.apiIncident(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != http.StatusBadRequest {
		t.Errorf("no params = %d, want 400", w.Code)
	}
}

func TestAPIIncidentWithIPMatchesFindings(t *testing.T) {
	s := newTestServerWithBbolt(t, "tok")
	now := time.Now()
	s.store.AppendHistory([]alert.Finding{
		{Severity: alert.Critical, Check: "brute_force", Message: "SSH from 203.0.113.5", Details: "many attempts", Timestamp: now},
		{Severity: alert.Warning, Check: "waf_status", Message: "unrelated", Timestamp: now},
	})

	w := httptest.NewRecorder()
	s.apiIncident(w, httptest.NewRequest("GET", "/?ip=203.0.113.5", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	var resp map[string]interface{}
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["query_ip"] != "203.0.113.5" {
		t.Errorf("query_ip = %v", resp["query_ip"])
	}
}

func TestAPIIncidentWithAccountMatchesPath(t *testing.T) {
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
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["query_account"] != "alice" {
		t.Errorf("query_account = %v", resp["query_account"])
	}
}

func TestAPIIncidentHoursCappedAt720(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	s.apiIncident(w, httptest.NewRequest("GET", "/?ip=203.0.113.5&hours=9999", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	var resp map[string]interface{}
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["hours"].(float64) != 720 {
		t.Errorf("hours = %v, want 720", resp["hours"])
	}
}

// =========================================================================
// suppressions_api.go — full CRUD cycle
// =========================================================================

func TestAPISuppressionsGETReturnsEmptyArray(t *testing.T) {
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

func TestAPISuppressionsCreateAndDelete(t *testing.T) {
	s := newTestServer(t, "tok")

	w := httptest.NewRecorder()
	body := `{"check":"webshell","path_pattern":"/home/alice/*","reason":"false positive"}`
	req := httptest.NewRequest("POST", "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	s.apiSuppressions(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("POST = %d, body = %s", w.Code, w.Body.String())
	}
	var created map[string]string
	_ = json.Unmarshal(w.Body.Bytes(), &created)
	if created["id"] == "" {
		t.Fatal("id should not be empty")
	}

	w = httptest.NewRecorder()
	req = httptest.NewRequest("DELETE", "/", strings.NewReader(`{"id":"`+created["id"]+`"}`))
	req.Header.Set("Content-Type", "application/json")
	s.apiSuppressions(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("DELETE = %d", w.Code)
	}
}

func TestAPISuppressionsPOSTMissingCheck(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", strings.NewReader(`{"reason":"test"}`))
	req.Header.Set("Content-Type", "application/json")
	s.apiSuppressions(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("missing check = %d, want 400", w.Code)
	}
}

func TestAPISuppressionsDeleteMissingIDField(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	req := httptest.NewRequest("DELETE", "/", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	s.apiSuppressions(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("missing ID = %d, want 400", w.Code)
	}
}

func TestAPISuppressionsUnsupportedMethod(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	s.apiSuppressions(w, httptest.NewRequest("PUT", "/", nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("PUT = %d, want 405", w.Code)
	}
}

// =========================================================================
// api.go — apiBlockedIPs legacy fallback (firewall/state.json)
// =========================================================================

func TestAPIBlockedIPsFallbackFirewallStateJSON(t *testing.T) {
	s := newTestServer(t, "tok")
	store.SetGlobal(nil)

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

func TestAPIBlockedIPsFallbackBlockedIPsJSON(t *testing.T) {
	s := newTestServer(t, "tok")
	store.SetGlobal(nil)

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

func TestAPIBlockedIPsNoDataReturnsEmpty(t *testing.T) {
	s := newTestServer(t, "tok")
	store.SetGlobal(nil)
	w := httptest.NewRecorder()
	s.apiBlockedIPs(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
}

// =========================================================================
// api.go — apiImport with whitelist, apiExport with bbolt
// =========================================================================

func TestAPIImportWithWhitelistEntries(t *testing.T) {
	s := newTestServerWithBbolt(t, "tok")
	body := `{"suppressions":[],"whitelist":[{"ip":"203.0.113.5"},{"ip":"198.51.100.1"}]}`
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	s.apiImport(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
}

func TestAPIExportBboltFields(t *testing.T) {
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
// api.go — apiHistory with all filters combined
// =========================================================================

func TestAPIHistoryCombinedFilters(t *testing.T) {
	s := newTestServerWithBbolt(t, "tok")
	now := time.Now()
	s.store.AppendHistory([]alert.Finding{
		{Severity: alert.Critical, Check: "webshell", Message: "found shell", Timestamp: now},
		{Severity: alert.Warning, Check: "waf_status", Message: "WAF off", Timestamp: now},
	})

	today := now.Format("2006-01-02")
	url := "/?from=" + today + "&to=" + today + "&severity=2&search=shell&checks=webshell&limit=10"
	w := httptest.NewRecorder()
	s.apiHistory(w, httptest.NewRequest("GET", url, nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
}

// =========================================================================
// api.go — buildBruteForceSummary, dedupIPReputation
// =========================================================================

func TestBuildBruteForceSummaryFields(t *testing.T) {
	ips := map[string]int{"203.0.113.1": 50, "203.0.113.2": 30}
	types := map[string]int{"wp-login": 40, "xmlrpc": 20}
	result := buildBruteForceSummary(ips, types)
	if result["total_attacks"].(int) != 60 {
		t.Errorf("total_attacks = %v", result["total_attacks"])
	}
	if result["unique_ips"].(int) != 2 {
		t.Errorf("unique_ips = %v", result["unique_ips"])
	}
}

func TestDedupIPReputationNoRegexMatch(t *testing.T) {
	items := []enrichedFinding{
		{Check: "ip_reputation", Message: "Some other format without IP"},
	}
	result := dedupIPReputation(items)
	if len(result) != 1 {
		t.Fatalf("expected 1, got %d", len(result))
	}
}

// =========================================================================
// api.go — apiTestAlert success path
// =========================================================================

func TestAPITestAlertDispatchSuccess(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	s.apiTestAlert(w, httptest.NewRequest("POST", "/", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	var resp map[string]interface{}
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["status"] != "sent" {
		t.Errorf("status = %v", resp["status"])
	}
}

// =========================================================================
// threat_api.go — apiThreatTopAttackers, apiThreatIP
// =========================================================================

func TestAPIThreatTopAttackersLimitCap(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	s.apiThreatTopAttackers(w, httptest.NewRequest("GET", "/?limit=9999", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
}

func TestAPIThreatIPValidPublicIPNoGeo(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	s.apiThreatIP(w, httptest.NewRequest("GET", "/?ip=203.0.113.5", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
}
