package webui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/store"
)

func modsecBlockSev(ip, host, rule string, sev alert.Severity, ts time.Time) alert.Finding {
	return alert.Finding{
		Check:     "modsec_block",
		Severity:  sev,
		Message:   "ModSecurity block from " + ip + " on " + host,
		Details:   "Rule: " + rule + "\nMessage: Test rule\nHostname: " + host + "\nURI: /x",
		Timestamp: ts,
	}
}

func TestModsecWindowParsing(t *testing.T) {
	cases := map[string]time.Duration{
		"1h":    time.Hour,
		"6h":    6 * time.Hour,
		"24h":   24 * time.Hour,
		"":      24 * time.Hour,
		"bogus": 24 * time.Hour,
	}
	for q, want := range cases {
		r := httptest.NewRequest("GET", "/?window="+q, nil)
		if got := modsecWindow(r); got != want {
			t.Errorf("modsecWindow(%q) = %v, want %v", q, got, want)
		}
	}
}

func TestModsecSeverityFilterParsing(t *testing.T) {
	cases := []struct {
		q   string
		sev alert.Severity
		ok  bool
	}{
		{"warning", alert.Warning, true},
		{"high", alert.High, true},
		{"critical", alert.Critical, true},
		{"CRITICAL", alert.Critical, true},
		{"", 0, false},
		{"bogus", 0, false},
	}
	for _, tc := range cases {
		r := httptest.NewRequest("GET", "/?severity="+tc.q, nil)
		sev, ok := modsecSeverityFilter(r)
		if ok != tc.ok || (ok && sev != tc.sev) {
			t.Errorf("modsecSeverityFilter(%q) = (%v,%v), want (%v,%v)", tc.q, sev, ok, tc.sev, tc.ok)
		}
	}
}

func TestAPIModSecBlocksWindowFilter(t *testing.T) {
	s := newTestServerWithBbolt(t, "tok")
	sdb := store.Global()
	now := time.Now()
	if err := sdb.AppendHistory([]alert.Finding{
		modsecBlockSev("203.0.113.10", "a.example.com", "900113", alert.Warning, now.Add(-2*time.Hour)),
		modsecBlockSev("203.0.113.11", "b.example.com", "900116", alert.Warning, now.Add(-30*time.Minute)),
	}); err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	s.apiModSecBlocks(w, httptest.NewRequest("GET", "/?window=1h", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status %d", w.Code)
	}
	var resp []modsecBlockView
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if len(resp) != 1 || resp[0].IP != "203.0.113.11" {
		t.Fatalf("window=1h got %d rows %+v, want only the 30m-old IP", len(resp), resp)
	}
}

func TestAPIModSecBlocksSeverityFilter(t *testing.T) {
	s := newTestServerWithBbolt(t, "tok")
	sdb := store.Global()
	now := time.Now()
	if err := sdb.AppendHistory([]alert.Finding{
		modsecBlockSev("203.0.113.20", "a.example.com", "900113", alert.Warning, now.Add(-10*time.Minute)),
		modsecBlockSev("203.0.113.21", "b.example.com", "900116", alert.Critical, now.Add(-5*time.Minute)),
	}); err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	s.apiModSecBlocks(w, httptest.NewRequest("GET", "/?severity=critical", nil))
	var resp []modsecBlockView
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if len(resp) != 1 || resp[0].IP != "203.0.113.21" {
		t.Fatalf("severity=critical got %+v, want only the critical IP", resp)
	}
}

func TestAPIModSecStatsWindowAndSeverityFilters(t *testing.T) {
	s := newTestServerWithBbolt(t, "tok")
	sdb := store.Global()
	now := time.Now()
	if err := sdb.AppendHistory([]alert.Finding{
		modsecBlockSev("203.0.113.31", "a.example.com", "900113", alert.Warning, now.Add(-10*time.Minute)),
		modsecBlockSev("203.0.113.32", "b.example.com", "900116", alert.Critical, now.Add(-5*time.Minute)),
		modsecBlockSev("203.0.113.33", "c.example.com", "900117", alert.Critical, now.Add(-2*time.Hour)),
	}); err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	s.apiModSecStats(w, httptest.NewRequest("GET", "/?window=1h&severity=critical", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status %d", w.Code)
	}
	var resp struct {
		Total     int    `json:"total"`
		UniqueIPs int    `json:"unique_ips"`
		TopRule   string `json:"top_rule"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Total != 1 || resp.UniqueIPs != 1 || resp.TopRule != "900116" {
		t.Fatalf("filtered stats = %+v, want one recent critical 900116 block", resp)
	}
}

func TestAPIModSecBlocksIncludesCountryField(t *testing.T) {
	s := newTestServerWithBbolt(t, "tok")
	sdb := store.Global()
	if err := sdb.AppendHistory([]alert.Finding{
		modsecBlockSev("203.0.113.30", "a.example.com", "900113", alert.Warning, time.Now()),
	}); err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	s.apiModSecBlocks(w, httptest.NewRequest("GET", "/", nil))
	var raw []map[string]json.RawMessage
	if err := json.Unmarshal(w.Body.Bytes(), &raw); err != nil {
		t.Fatal(err)
	}
	if len(raw) != 1 {
		t.Fatalf("got %d rows", len(raw))
	}
	if _, ok := raw[0]["country"]; !ok {
		t.Errorf("block view missing country field: %v", raw[0])
	}
}

func TestAPIModSecEventsWindowAndSeverity(t *testing.T) {
	s := newTestServerWithBbolt(t, "tok")
	sdb := store.Global()
	now := time.Now()
	if err := sdb.AppendHistory([]alert.Finding{
		modsecBlockSev("203.0.113.40", "a.example.com", "900113", alert.Warning, now.Add(-2*time.Hour)),
		modsecBlockSev("203.0.113.41", "b.example.com", "900116", alert.Critical, now.Add(-10*time.Minute)),
	}); err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	s.apiModSecEvents(w, httptest.NewRequest("GET", "/?window=1h&severity=critical", nil))
	var resp []modsecEventView
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if len(resp) != 1 || resp[0].IP != "203.0.113.41" {
		t.Fatalf("events window+severity got %+v, want only critical recent", resp)
	}
}

func TestModsecCountryOfNilDBReturnsEmpty(t *testing.T) {
	s := &Server{}
	if c, _ := s.modsecCountryOf("203.0.113.1"); c != "" {
		t.Errorf("country with nil geoip = %q, want empty", c)
	}
}
