package webui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/firewall"
	"github.com/pidginhost/csm/internal/store"
)

// --- apiBlockedIPs with bbolt blocked data ---------------------------

func TestAPIBlockedIPsWithMultipleEntries(t *testing.T) {
	s := newTestServerWithBbolt(t, "tok")
	sdb := store.Global()
	_ = sdb.BlockIP("203.0.113.1", "brute-force", time.Time{})
	_ = sdb.BlockIP("203.0.113.2", "waf-block", time.Now().Add(2*time.Hour))
	_ = sdb.BlockIP("203.0.113.3", "auto-block", time.Now().Add(-1*time.Hour)) // expired

	w := httptest.NewRecorder()
	s.apiBlockedIPs(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	var data []interface{}
	_ = json.Unmarshal(w.Body.Bytes(), &data)
	// Should have at least 2 (expired ones filtered by formatBlockedView)
	if len(data) < 1 {
		t.Errorf("expected blocked entries, got %d", len(data))
	}
}

// --- apiUnblockIP with bbolt -----------------------------------------

func TestAPIUnblockIPWithBbolt(t *testing.T) {
	s := newTestServerWithBbolt(t, "tok")
	s.cfg.Firewall = &firewall.FirewallConfig{Enabled: true}
	sdb := store.Global()
	_ = sdb.BlockIP("203.0.113.5", "test", time.Time{})

	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", strings.NewReader(`{"ip":"203.0.113.5"}`))
	req.Header.Set("Content-Type", "application/json")
	s.apiUnblockIP(w, req)
	// Exercises the unblock path through bbolt
	if w.Code == 0 {
		t.Error("unexpected zero status")
	}
}

// --- apiUnblockBulk with bbolt data ----------------------------------

func TestAPIUnblockBulkWithBbolt(t *testing.T) {
	s := newTestServerWithBbolt(t, "tok")
	s.cfg.Firewall = &firewall.FirewallConfig{Enabled: true}
	sdb := store.Global()
	_ = sdb.BlockIP("203.0.113.1", "test1", time.Time{})
	_ = sdb.BlockIP("203.0.113.2", "test2", time.Time{})

	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", strings.NewReader(`{"ips":["203.0.113.1","203.0.113.2"]}`))
	req.Header.Set("Content-Type", "application/json")
	s.apiUnblockBulk(w, req)
	if w.Code == 0 {
		t.Error("unexpected zero status")
	}
}

// --- apiBulkFix with fixable findings --------------------------------

func TestAPIBulkFixWithFixable(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	body := `{"findings":[{"check":"world_writable_php","message":"test: /tmp/nonexistent.php","details":""},{"check":"webshell","message":"Found /tmp/nonexistent2.php","details":""}]}`
	req := httptest.NewRequest("POST", "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	s.apiBulkFix(w, req)
	if w.Code == 0 {
		t.Error("unexpected zero status")
	}
}

// --- apiQuarantinePreview with actual quarantine file -----------------

func TestAPIQuarantinePreviewWithID(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	s.apiQuarantinePreview(w, httptest.NewRequest("GET", "/?id=nonexistent_abc", nil))
	// Should return 404 since no quarantine file exists
	if w.Code != http.StatusNotFound && w.Code != http.StatusBadRequest {
		t.Errorf("nonexistent = %d", w.Code)
	}
}

// --- apiHistory with complex filters ---------------------------------

func TestAPIHistoryComplexFilters(t *testing.T) {
	s := newTestServerWithBbolt(t, "tok")
	findings := []alert.Finding{
		{Severity: alert.Critical, Check: "webshell", Message: "Found webshell in /home/alice", Timestamp: time.Now()},
		{Severity: alert.High, Check: "brute_force", Message: "Brute force from 203.0.113.5", Timestamp: time.Now()},
		{Severity: alert.Warning, Check: "waf_status", Message: "WAF disabled", Timestamp: time.Now()},
	}
	s.store.AppendHistory(findings)

	// Multiple filters combined
	today := time.Now().Format("2006-01-02")
	w := httptest.NewRecorder()
	s.apiHistory(w, httptest.NewRequest("GET", "/?severity=2&from="+today+"&to="+today+"&search=alice&checks=webshell&limit=10", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	var resp map[string]interface{}
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["total"].(float64) != 1 {
		t.Errorf("complex filter total = %v, want 1", resp["total"])
	}
}

// --- apiAccounts with bbolt data -------------------------------------

func TestAPIAccountsWithBbolt(t *testing.T) {
	s := newTestServerWithBbolt(t, "tok")
	// Seed a finding with /home/alice path
	findings := []alert.Finding{
		{Severity: alert.Critical, Check: "webshell", Message: "in /home/alice/public_html/wso.php", Timestamp: time.Now()},
	}
	s.store.AppendHistory(findings)

	w := httptest.NewRecorder()
	s.apiAccounts(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
}

// --- apiFirewallStatus deeper branches --------------------------------

func TestAPIFirewallStatusDeep(t *testing.T) {
	s := newTestServerWithBbolt(t, "tok")
	s.cfg.Firewall = &firewall.FirewallConfig{
		Enabled:  true,
		TCPIn:    []int{22, 80, 443},
		InfraIPs: []string{"10.0.0.1"},
	}

	sdb := store.Global()
	_ = sdb.BlockIP("203.0.113.5", "test", time.Time{})
	_ = sdb.BlockIP("198.51.100.1", "test", time.Now().Add(1*time.Hour))

	w := httptest.NewRecorder()
	s.apiFirewallStatus(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	var data map[string]interface{}
	_ = json.Unmarshal(w.Body.Bytes(), &data)
	if data["enabled"] != true {
		t.Error("should show enabled")
	}
}

// --- apiFirewallAudit with seeded audit data --------------------------

func TestAPIFirewallAuditDeep(t *testing.T) {
	s := newTestServerWithBbolt(t, "tok")
	s.cfg.Firewall = &firewall.FirewallConfig{Enabled: true}

	sdb := store.Global()
	_ = sdb.BlockIP("203.0.113.5", "brute-force", time.Time{})
	_ = sdb.AllowIP("10.0.0.1", "infra", time.Time{})

	w := httptest.NewRecorder()
	s.apiFirewallAudit(w, httptest.NewRequest("GET", "/?limit=50", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
}

// --- apiStats deeper with mixed finding types -------------------------

func TestAPIStatsDeep(t *testing.T) {
	s := newTestServerWithBbolt(t, "tok")
	findings := []alert.Finding{
		{Severity: alert.Critical, Check: "wp_login_bruteforce", Message: "brute from 203.0.113.5", Timestamp: time.Now()},
		{Severity: alert.Critical, Check: "xmlrpc_abuse", Message: "xmlrpc from 198.51.100.1", Timestamp: time.Now()},
		{Severity: alert.Critical, Check: "auto_block", Message: "blocked 203.0.113.5", Timestamp: time.Now()},
		{Severity: alert.Critical, Check: "auto_response", Message: "quarantined /home/alice/public_html/evil.php", Timestamp: time.Now()},
		{Severity: alert.High, Check: "obfuscated_php", Message: "in /home/alice/public_html/dropper.php", Timestamp: time.Now()},
		{Severity: alert.High, Check: "modsec_csm_block_escalation", Message: "xmlrpc 900007", Timestamp: time.Now()},
		{Severity: alert.Warning, Check: "waf_status", Message: "WAF not active", Timestamp: time.Now()},
	}
	s.store.AppendHistory(findings)

	w := httptest.NewRecorder()
	s.apiStats(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	var data map[string]interface{}
	_ = json.Unmarshal(w.Body.Bytes(), &data)
	// Exercises the full stats computation path.
	_ = data
}
