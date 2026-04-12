package webui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/store"
)

// newTestServerWithBbolt creates a server backed by a real bbolt store
// so history/blocked/stats APIs exercise the full code paths.
func newTestServerWithBbolt(t *testing.T, token string) *Server {
	t.Helper()
	s := newTestServer(t, token)
	dir := t.TempDir()
	sdb, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		store.SetGlobal(nil)
		_ = sdb.Close()
	})
	store.SetGlobal(sdb)
	return s
}

// --- apiHistory with filters -----------------------------------------

func TestAPIHistoryWithFilters(t *testing.T) {
	s := newTestServerWithBbolt(t, "tok")
	// Seed findings
	findings := []alert.Finding{
		{Severity: alert.Critical, Check: "webshell", Message: "found shell", Timestamp: time.Now()},
		{Severity: alert.Warning, Check: "waf_status", Message: "WAF off", Timestamp: time.Now()},
	}
	s.store.AppendHistory(findings)

	// Filter by check
	w := httptest.NewRecorder()
	s.apiHistory(w, httptest.NewRequest("GET", "/?checks=webshell&limit=10", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	var resp map[string]interface{}
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["total"].(float64) != 1 {
		t.Errorf("filtered total = %v, want 1", resp["total"])
	}
}

func TestAPIHistoryWithSeverityFilter(t *testing.T) {
	s := newTestServerWithBbolt(t, "tok")
	findings := []alert.Finding{
		{Severity: alert.Critical, Check: "test", Message: "crit", Timestamp: time.Now()},
		{Severity: alert.Warning, Check: "test2", Message: "warn", Timestamp: time.Now()},
	}
	s.store.AppendHistory(findings)

	w := httptest.NewRecorder()
	s.apiHistory(w, httptest.NewRequest("GET", "/?severity=2&limit=10", nil)) // 2 = Critical
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
}

func TestAPIHistoryWithSearch(t *testing.T) {
	s := newTestServerWithBbolt(t, "tok")
	findings := []alert.Finding{
		{Severity: alert.Critical, Check: "webshell", Message: "Found shell in /home/alice", Timestamp: time.Now()},
		{Severity: alert.Warning, Check: "waf", Message: "WAF disabled", Timestamp: time.Now()},
	}
	s.store.AppendHistory(findings)

	w := httptest.NewRecorder()
	s.apiHistory(w, httptest.NewRequest("GET", "/?search=alice&limit=10", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	var resp map[string]interface{}
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["total"].(float64) != 1 {
		t.Errorf("search total = %v, want 1", resp["total"])
	}
}

func TestAPIHistoryWithDateRange(t *testing.T) {
	s := newTestServerWithBbolt(t, "tok")
	findings := []alert.Finding{
		{Severity: alert.Critical, Check: "test", Message: "today", Timestamp: time.Now()},
	}
	s.store.AppendHistory(findings)

	today := time.Now().Format("2006-01-02")
	w := httptest.NewRecorder()
	s.apiHistory(w, httptest.NewRequest("GET", "/?from="+today+"&to="+today+"&limit=10", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
}

func TestAPIHistoryPagination(t *testing.T) {
	s := newTestServerWithBbolt(t, "tok")
	// Seed enough for pagination
	for i := 0; i < 5; i++ {
		s.store.AppendHistory([]alert.Finding{
			{Severity: alert.Warning, Check: "test", Message: "msg", Timestamp: time.Now()},
		})
	}

	w := httptest.NewRecorder()
	s.apiHistory(w, httptest.NewRequest("GET", "/?limit=2&offset=0", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	var resp map[string]interface{}
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["limit"].(float64) != 2 {
		t.Errorf("limit = %v", resp["limit"])
	}
}

// --- apiBlockedIPs with bbolt data -----------------------------------

func TestAPIBlockedIPsWithBbolt(t *testing.T) {
	s := newTestServerWithBbolt(t, "tok")
	sdb := store.Global()
	_ = sdb.BlockIP("203.0.113.5", "brute-force", time.Time{})
	_ = sdb.BlockIP("198.51.100.1", "waf-block", time.Now().Add(1*time.Hour))

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
		t.Error("expected at least 1 blocked IP")
	}
}

// --- apiStats via bbolt (exercises buildBruteForceSummary etc.) -------

func TestAPIStatsViaBbolt(t *testing.T) {
	s := newTestServerWithBbolt(t, "tok")
	findings := []alert.Finding{
		{Severity: alert.Critical, Check: "wp_login_bruteforce", Message: "brute from 203.0.113.5", Timestamp: time.Now()},
		{Severity: alert.Critical, Check: "auto_block", Message: "blocked 203.0.113.5", Timestamp: time.Now()},
		{Severity: alert.High, Check: "obfuscated_php", Message: "in /home/alice/public_html/evil.php", Timestamp: time.Now()},
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
}

// --- apiImport with suppressions + bbolt -----------------------------

func TestAPIImportWithSuppressions(t *testing.T) {
	s := newTestServerWithBbolt(t, "tok")
	body := `{"suppressions":[{"id":"s1","check":"test","reason":"testing"}],"whitelist":[]}`
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	s.apiImport(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
	var resp map[string]interface{}
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["imported"].(float64) != 1 {
		t.Errorf("imported = %v, want 1", resp["imported"])
	}
}
