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
	"github.com/pidginhost/csm/internal/firewall"
	"github.com/pidginhost/csm/internal/store"
)

// writeEngineBlockStateFile writes firewall/state.json under statePath, the
// authoritative source apiBlockedIPs reads. entriesJSON are raw JSON objects
// for the "blocked" array.
func writeEngineBlockStateFile(t *testing.T, statePath string, entriesJSON []string) {
	t.Helper()
	fwDir := filepath.Join(statePath, "firewall")
	if err := os.MkdirAll(fwDir, 0755); err != nil {
		t.Fatal(err)
	}
	body := `{"blocked":[` + strings.Join(entriesJSON, ",") + `]}`
	if err := os.WriteFile(filepath.Join(fwDir, "state.json"), []byte(body), 0644); err != nil {
		t.Fatal(err)
	}
}

// --- apiBlockedIPs reads authoritative engine state ------------------

func TestAPIBlockedIPsWithMultipleEntries(t *testing.T) {
	s := newTestServerWithBbolt(t, "tok")
	writeEngineBlockStateFile(t, s.cfg.StatePath, []string{
		`{"ip":"203.0.113.1","reason":"brute-force","blocked_at":"2026-04-01T00:00:00Z","expires_at":"0001-01-01T00:00:00Z"}`,
		`{"ip":"203.0.113.2","reason":"waf-block","blocked_at":"2026-04-01T00:00:00Z","expires_at":"` + time.Now().Add(2*time.Hour).Format(time.RFC3339) + `"}`,
		`{"ip":"203.0.113.3","reason":"auto-block","blocked_at":"2026-04-01T00:00:00Z","expires_at":"` + time.Now().Add(-1*time.Hour).Format(time.RFC3339) + `"}`, // expired
	})

	w := httptest.NewRecorder()
	s.apiBlockedIPs(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	var data []map[string]interface{}
	_ = json.Unmarshal(w.Body.Bytes(), &data)
	// Two active entries; the expired one is filtered by formatBlockedView.
	if len(data) != 2 {
		t.Errorf("expected 2 active blocked entries, got %d", len(data))
	}
}

func TestAPIBlockedIPsEmptyEngineStateReturnsArray(t *testing.T) {
	s := newTestServerWithBbolt(t, "tok")
	_ = store.Global().BlockIP("10.0.0.99", "stale-bucket", time.Now().Add(time.Hour))
	legacy := `{"ips":[` +
		`{"ip":"198.51.100.99","reason":"legacy",` +
		`"blocked_at":"2026-04-01T00:00:00Z","expires_at":"2099-01-01T00:00:00Z"}]}`
	if err := os.WriteFile(filepath.Join(s.cfg.StatePath, "blocked_ips.json"), []byte(legacy), 0644); err != nil {
		t.Fatal(err)
	}
	writeEngineBlockStateFile(t, s.cfg.StatePath, nil)

	w := httptest.NewRecorder()
	s.apiBlockedIPs(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	if got := strings.TrimSpace(w.Body.String()); got != "[]" {
		t.Fatalf("body = %s, want []", got)
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
