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

func TestAPIHistoryDateOnlyToIncludesLastSecondFractions(t *testing.T) {
	s := newTestServerWithBbolt(t, "tok")
	day := time.Now().AddDate(0, 0, -1)
	ts := time.Date(day.Year(), day.Month(), day.Day(), 23, 59, 59, int(500*time.Millisecond), time.Local)
	s.store.AppendHistory([]alert.Finding{
		{Severity: alert.Critical, Check: "test", Message: "late same day", Timestamp: ts},
	})

	date := ts.Format("2006-01-02")
	w := httptest.NewRecorder()
	s.apiHistory(w, httptest.NewRequest("GET", "/?from="+date+"&to="+date+"&limit=10", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp["total"].(float64) != 1 {
		t.Fatalf("total = %v, want 1", resp["total"])
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

func TestAPIHistoryFilteredOffsetPastEnd(t *testing.T) {
	s := newTestServerWithBbolt(t, "tok")
	s.store.AppendHistory([]alert.Finding{
		{Severity: alert.Warning, Check: "test", Message: "msg", Timestamp: time.Now()},
	})

	w := httptest.NewRecorder()
	s.apiHistory(w, httptest.NewRequest("GET", "/?search=msg&offset=100&limit=10", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	var resp map[string]interface{}
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	findings := resp["findings"]
	if findings != nil {
		arr, ok := findings.([]interface{})
		if ok && len(arr) > 0 {
			t.Error("offset past end should return empty findings")
		}
	}
}

func TestAPIHistoryLargeLimit(t *testing.T) {
	s := newTestServerWithBbolt(t, "tok")
	w := httptest.NewRecorder()
	s.apiHistory(w, httptest.NewRequest("GET", "/?limit=99999", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
}

func TestAPIHistoryFilteredExactScanCapIsNotMarkedTruncated(t *testing.T) {
	s := newTestServerWithBbolt(t, "tok")
	base := time.Now().Add(-time.Hour)
	findings := make([]alert.Finding, 0, historyFilterScanCap)
	for i := 0; i < historyFilterScanCap; i++ {
		findings = append(findings, alert.Finding{
			Severity:  alert.Warning,
			Check:     "scan_cap_exact",
			Message:   "cap-row",
			Timestamp: base.Add(time.Duration(i) * time.Millisecond),
		})
	}
	s.store.AppendHistory(findings)

	w := httptest.NewRecorder()
	s.apiHistory(w, httptest.NewRequest("GET", "/?search=cap-row&limit=1", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
	if got := w.Header().Get("X-CSM-Truncated"); got != "" {
		t.Fatalf("X-CSM-Truncated = %q, want unset when history count exactly equals scan cap", got)
	}
	var resp struct {
		Total     int  `json:"total"`
		Truncated bool `json:"truncated"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.Total != historyFilterScanCap {
		t.Fatalf("total = %d, want %d", resp.Total, historyFilterScanCap)
	}
	if resp.Truncated {
		t.Fatal("truncated = true, want false when no rows were omitted")
	}
}

func TestAPIBlockedIPsReadsEngineStateNotStore(t *testing.T) {
	s := newTestServerWithBbolt(t, "tok")
	// Stale migration-snapshot bucket: must be ignored by the handler.
	_ = store.Global().BlockIP("10.0.0.99", "stale-bucket", time.Now().Add(time.Hour))
	// Authoritative engine state.
	writeEngineBlockStateFile(t, s.cfg.StatePath, []string{
		`{"ip":"203.0.113.5","reason":"brute-force","blocked_at":"2026-04-01T00:00:00Z","expires_at":"0001-01-01T00:00:00Z"}`,
		`{"ip":"198.51.100.1","reason":"waf-block","blocked_at":"2026-04-01T00:00:00Z","expires_at":"` + time.Now().Add(1*time.Hour).Format(time.RFC3339) + `"}`,
	})

	w := httptest.NewRecorder()
	s.apiBlockedIPs(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	var data []map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &data); err != nil {
		t.Fatalf("bad JSON: %v", err)
	}
	ips := map[string]bool{}
	for _, e := range data {
		if ip, ok := e["ip"].(string); ok {
			ips[ip] = true
		}
	}
	if !ips["203.0.113.5"] || !ips["198.51.100.1"] {
		t.Errorf("engine-state blocked IPs missing: %v", ips)
	}
	if ips["10.0.0.99"] {
		t.Error("stale store-bucket IP leaked into response")
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

func TestAPIImportDedupesSuppressions(t *testing.T) {
	s := newTestServerWithBbolt(t, "tok")
	body := `{"suppressions":[{"id":"s1","check":"test","reason":"testing"}]}`
	for i := 0; i < 2; i++ {
		w := httptest.NewRecorder()
		req := httptest.NewRequest("POST", "/", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		s.apiImport(w, req)
	}
	rules := s.store.LoadSuppressions()
	if len(rules) != 1 {
		t.Errorf("expected 1 after dedup, got %d", len(rules))
	}
}

func TestAPIImportBadJSON(t *testing.T) {
	s := newTestServerWithBbolt(t, "tok")
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", strings.NewReader(`{bad json`))
	req.Header.Set("Content-Type", "application/json")
	s.apiImport(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("bad JSON = %d, want 400", w.Code)
	}
}

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
