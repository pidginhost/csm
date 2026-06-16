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

// TestAPIHistoryEmitsStructuredAccountAndIP pins item 6: the history endpoint
// attaches the account and attacker IP from the finding's structured fields so
// the email UI no longer regex-scrapes the human-readable message (which is
// IPv4-only and breaks on any wording change). The IPv6 SourceIP below is the
// case the old `/from (\d+\.\d+\.\d+\.\d+)/` regex silently dropped.
func TestAPIHistoryEmitsStructuredAccountAndIP(t *testing.T) {
	s := newTestServerWithBbolt(t, "tok")
	s.store.AppendHistory([]alert.Finding{
		{Severity: alert.Critical, Check: "mail_bruteforce", Message: "Mail brute force burst", Mailbox: "user@example.com", SourceIP: "2001:db8::1", Timestamp: time.Now()},
		{Severity: alert.High, Check: "obfuscated_php", Message: "shell in /home/bob/public_html/evil.php", Timestamp: time.Now()},
		{Severity: alert.Warning, Check: "mail_filter", Message: "filter rule forwards mail", Domain: "example.net", Timestamp: time.Now()},
	})

	w := httptest.NewRecorder()
	s.apiHistory(w, httptest.NewRequest("GET", "/?limit=10", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	var resp struct {
		Findings []struct {
			Check   string `json:"check"`
			Account string `json:"account"`
			IP      string `json:"ip"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	type pair struct{ acct, ip string }
	got := map[string]pair{}
	for _, f := range resp.Findings {
		got[f.Check] = pair{f.Account, f.IP}
	}
	if g := got["mail_bruteforce"]; g.acct != "user@example.com" || g.ip != "2001:db8::1" {
		t.Errorf("mail_bruteforce account/ip = %q/%q, want user@example.com/2001:db8::1 (IPv6 must survive)", g.acct, g.ip)
	}
	if g := got["obfuscated_php"]; g.acct != "bob" {
		t.Errorf("obfuscated_php account = %q, want bob (from /home path)", g.acct)
	}
	if g := got["mail_filter"]; g.acct != "example.net" {
		t.Errorf("mail_filter account = %q, want example.net (domain fallback)", g.acct)
	}
}

func TestHistoryFindingAccountIPFallbacks(t *testing.T) {
	findings := withAccountIP([]alert.Finding{
		{
			Check:     "email_auth_failure_realtime",
			TenantID:  "localuser",
			SourceIP:  "2001:db8::2",
			Timestamp: time.Now(),
		},
		{
			Check:   "email_auth_failure_realtime",
			Details: "dovecot_login authenticator failed for H=(bad) [2001:db8::3]:465: 535 Incorrect authentication data (set_id=legacy@example.com)",
		},
		{
			Check:   "email_compromised_account",
			Message: "Account old@example.net is on cPanel outgoing mail hold",
		},
		{
			Check:   "mail_bruteforce",
			Message: "Mail auth brute force from 198.51.100.12: 10 failed auths in 1m0s",
		},
		{
			Check:   "email_suspicious_geo",
			Message: "Suspicious email login for geo@example.com from ZZ - previously seen: none",
			Details: "dovecot: imap-login: Login: user=<geo@example.com>, rip=2001:db8::4, lip=10.0.0.1",
		},
		{
			Check:   "email_weak_password",
			Message: "Weak email password for oldbox@example.org (account: cpuser)",
			Details: "Account: cpuser\nMailbox: oldbox@example.org\nMatch type: heuristic",
		},
		{
			Check:   "webshell",
			Message: "Account ignored@example.net from 192.0.2.44",
		},
	})

	tests := []struct {
		name        string
		got         historyFinding
		wantAccount string
		wantIP      string
	}{
		{
			name:        "bare cpanel account",
			got:         findings[0],
			wantAccount: "localuser",
			wantIP:      "2001:db8::2",
		},
		{
			name:        "legacy set_id and bracketed ipv6",
			got:         findings[1],
			wantAccount: "legacy@example.com",
			wantIP:      "2001:db8::3",
		},
		{
			name:        "legacy message account",
			got:         findings[2],
			wantAccount: "old@example.net",
		},
		{
			name:   "legacy message ipv4 with trailing colon",
			got:    findings[3],
			wantIP: "198.51.100.12",
		},
		{
			name:        "legacy rip token ipv6",
			got:         findings[4],
			wantAccount: "geo@example.com",
			wantIP:      "2001:db8::4",
		},
		{
			name:        "legacy email account beats cpanel detail",
			got:         findings[5],
			wantAccount: "oldbox@example.org",
		},
		{
			name: "non email message ignored",
			got:  findings[6],
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got.Account != tt.wantAccount {
				t.Errorf("Account = %q, want %q", tt.got.Account, tt.wantAccount)
			}
			if tt.got.IP != tt.wantIP {
				t.Errorf("IP = %q, want %q", tt.got.IP, tt.wantIP)
			}
		})
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

const oldHistoryFilterScanCap = 5000

func TestAPIHistoryChecksDateFilterFindsRowsOlderThanOldScanCap(t *testing.T) {
	s := newTestServerWithBbolt(t, "tok")
	oldDay := time.Date(2026, 1, 2, 12, 0, 0, 0, time.Local)
	s.store.AppendHistory([]alert.Finding{
		{Severity: alert.High, Check: "old-target", Message: "older row", Timestamp: oldDay},
	})

	newer := time.Date(2026, 2, 1, 0, 0, 0, 0, time.Local)
	findings := make([]alert.Finding, 0, oldHistoryFilterScanCap+1)
	for i := 0; i < oldHistoryFilterScanCap+1; i++ {
		findings = append(findings, alert.Finding{
			Severity:  alert.Warning,
			Check:     "newer-noise",
			Message:   "outside requested day",
			Timestamp: newer.Add(time.Duration(i) * time.Second),
		})
	}
	s.store.AppendHistory(findings)

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/?checks=old-target&from=2026-01-02&to=2026-01-02&limit=10", nil)
	s.apiHistory(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
	if got := w.Header().Get("X-CSM-Truncated"); got != "" {
		t.Fatalf("X-CSM-Truncated = %q, want unset for exact store-filtered results", got)
	}
	var resp struct {
		Findings  []alert.Finding `json:"findings"`
		Total     int             `json:"total"`
		Truncated bool            `json:"truncated"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.Total != 1 {
		t.Fatalf("total = %d, want 1", resp.Total)
	}
	if len(resp.Findings) != 1 || resp.Findings[0].Check != "old-target" {
		t.Fatalf("findings = %+v, want old-target only", resp.Findings)
	}
	if resp.Truncated {
		t.Fatal("truncated = true, want false for exact store-filtered results")
	}
}

func TestAPIHistoryDateFilterFindsRowsOlderThanScanCap(t *testing.T) {
	s := newTestServerWithBbolt(t, "tok")
	oldDay := time.Date(2026, 1, 2, 12, 0, 0, 0, time.Local)
	s.store.AppendHistory([]alert.Finding{
		{Severity: alert.High, Check: "old-target", Message: "older row", Timestamp: oldDay},
	})

	newer := time.Date(2026, 2, 1, 0, 0, 0, 0, time.Local)
	findings := make([]alert.Finding, 0, oldHistoryFilterScanCap+1)
	for i := 0; i < oldHistoryFilterScanCap+1; i++ {
		findings = append(findings, alert.Finding{
			Severity:  alert.Warning,
			Check:     "newer-noise",
			Message:   "outside requested day",
			Timestamp: newer.Add(time.Duration(i) * time.Second),
		})
	}
	s.store.AppendHistory(findings)

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/?from=2026-01-02&to=2026-01-02&limit=10", nil)
	s.apiHistory(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
	if got := w.Header().Get("X-CSM-Truncated"); got != "" {
		t.Fatalf("X-CSM-Truncated = %q, want unset for exact store-filtered results", got)
	}
	var resp struct {
		Findings  []alert.Finding `json:"findings"`
		Total     int             `json:"total"`
		Truncated bool            `json:"truncated"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.Total != 1 {
		t.Fatalf("total = %d, want 1", resp.Total)
	}
	if len(resp.Findings) != 1 || resp.Findings[0].Check != "old-target" {
		t.Fatalf("findings = %+v, want old-target only", resp.Findings)
	}
	if resp.Truncated {
		t.Fatal("truncated = true, want false for exact store-filtered results")
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
