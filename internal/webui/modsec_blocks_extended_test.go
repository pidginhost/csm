package webui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/store"
)

// modsecBlock helper: synthesise a ModSecurity finding for the bbolt store.
func modsecBlock(ip, host, uri, rule string, ts time.Time) alert.Finding {
	return alert.Finding{
		Check:     "modsec_block",
		Severity:  alert.Warning,
		Message:   "ModSecurity block from " + ip + " on " + host,
		Details:   "Rule: " + rule + "\nMessage: Test rule\nHostname: " + host + "\nURI: " + uri,
		Timestamp: ts,
	}
}

func TestModSecBlocksExtendedFieldsPopulated(t *testing.T) {
	s := newTestServerWithBbolt(t, "tok")
	sdb := store.Global()

	now := time.Now()
	older := now.Add(-30 * time.Minute)

	if err := sdb.AppendHistory([]alert.Finding{
		modsecBlock("203.0.113.50", "example.com", "/wp-login.php", "900113", older),
		modsecBlock("203.0.113.50", "example.com", "/wp-login.php", "900113", now.Add(-15*time.Minute)),
		modsecBlock("203.0.113.50", "shop.example.com", "/admin", "900116", now.Add(-5*time.Minute)),
		modsecBlock("203.0.113.50", "example.com", "/wp-admin/index.php", "900113", now),
	}); err != nil {
		t.Fatal(err)
	}

	w := httptest.NewRecorder()
	s.apiModSecBlocks(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}

	var resp []modsecBlockView
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v\nbody: %s", err, w.Body.String())
	}
	if len(resp) != 2 {
		t.Fatalf("got %d block rows, want 2 (one per IP+rule)", len(resp))
	}

	var row modsecBlockView
	for _, candidate := range resp {
		if candidate.RuleID == "900113" {
			row = candidate
			break
		}
	}
	if row.RuleID == "" {
		t.Fatalf("missing row for rule 900113: %+v", resp)
	}
	if row.Hits != 3 {
		t.Errorf("Hits = %d, want 3", row.Hits)
	}
	if row.DomainCount != 1 {
		t.Errorf("DomainCount = %d, want 1 (example.com)", row.DomainCount)
	}
	if len(row.DomainList) != 1 || row.DomainList[0] != "example.com" {
		t.Errorf("DomainList = %v, want [example.com]", row.DomainList)
	}
	if row.FirstSeen == "" {
		t.Error("FirstSeen empty -- phase 8.4 must populate RFC3339 first_seen")
	}
	if row.LastSeenISO == "" {
		t.Error("LastSeenISO empty -- phase 8.4 must populate RFC3339 last_seen_iso")
	}
	// FirstSeen should be older than LastSeenISO.
	if row.FirstSeen >= row.LastSeenISO {
		t.Errorf("FirstSeen %q should be older than LastSeenISO %q", row.FirstSeen, row.LastSeenISO)
	}
	if len(row.TopURIs) == 0 {
		t.Error("TopURIs empty -- phase 8.4 must rank URIs hit by this IP")
	}
	// /wp-login.php was hit 2x and should rank ahead of single-hit URIs.
	if row.TopURIs[0] != "/wp-login.php" {
		t.Errorf("TopURIs[0] = %q, want /wp-login.php (most-hit)", row.TopURIs[0])
	}
	if len(row.SampleEvents) != 3 {
		t.Errorf("SampleEvents = %d, want 3 (cap)", len(row.SampleEvents))
	}
	for _, ev := range row.SampleEvents {
		if ev.RuleID == "" || ev.Hostname == "" || ev.Time == "" {
			t.Errorf("SampleEvent missing fields: %+v", ev)
		}
	}

	var second modsecBlockView
	for _, candidate := range resp {
		if candidate.RuleID == "900116" {
			second = candidate
			break
		}
	}
	if second.RuleID == "" {
		t.Fatalf("missing row for rule 900116: %+v", resp)
	}
	if second.Hits != 1 {
		t.Errorf("second Hits = %d, want 1", second.Hits)
	}
	if len(second.DomainList) != 1 || second.DomainList[0] != "shop.example.com" {
		t.Errorf("second DomainList = %v, want [shop.example.com]", second.DomainList)
	}
}

func TestModSecBlocksLegacyFieldsUnchanged(t *testing.T) {
	// The phase 8.4 extension is additive: existing JSON keys must keep
	// their previous semantics so external consumers do not break.
	s := newTestServerWithBbolt(t, "tok")
	sdb := store.Global()

	now := time.Now()
	if err := sdb.AppendHistory([]alert.Finding{
		modsecBlock("198.51.100.7", "site.test", "/x", "900113", now),
	}); err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	s.apiModSecBlocks(w, httptest.NewRequest("GET", "/", nil))

	var raw []map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &raw); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(raw) != 1 {
		t.Fatalf("rows = %d, want 1", len(raw))
	}
	for _, key := range []string{"ip", "rule_id", "description", "domains", "hits", "last_seen", "escalated"} {
		if _, ok := raw[0][key]; !ok {
			t.Errorf("legacy key %q missing from response", key)
		}
	}
}

func TestDeduplicateModSecFindingsKeepsDifferentDatesSameClockSecond(t *testing.T) {
	base := time.Date(2026, 5, 10, 15, 4, 5, 500, time.UTC)
	findings := []alert.Finding{
		modsecBlock("198.51.100.30", "site.test", "/today", "900113", base),
		modsecBlock("198.51.100.30", "site.test", "/yesterday", "900113", base.Add(-23*time.Hour)),
	}

	got := deduplicateModSecFindings(findings)
	if len(got) != 2 {
		t.Fatalf("deduped events = %d, want 2 for different dates with same clock second: %+v", len(got), got)
	}
}

func TestModSecEventsReturnsNewestFirst(t *testing.T) {
	s := newTestServerWithBbolt(t, "tok")
	sdb := store.Global()

	now := time.Now()
	if err := sdb.AppendHistory([]alert.Finding{
		modsecBlock("198.51.100.20", "site.test", "/old", "900113", now.Add(-20*time.Minute)),
		modsecBlock("198.51.100.21", "site.test", "/newer", "900113", now.Add(-10*time.Minute)),
		modsecBlock("198.51.100.22", "site.test", "/newest", "900113", now.Add(-1*time.Minute)),
	}); err != nil {
		t.Fatal(err)
	}

	w := httptest.NewRecorder()
	s.apiModSecEvents(w, httptest.NewRequest(http.MethodGet, "/api/v1/modsec/events?limit=2", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}

	var resp []modsecEventView
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v\nbody: %s", err, w.Body.String())
	}
	if len(resp) != 2 {
		t.Fatalf("events = %d, want 2: %+v", len(resp), resp)
	}
	if resp[0].URI != "/newest" || resp[1].URI != "/newer" {
		t.Fatalf("events order = [%q, %q], want newest first", resp[0].URI, resp[1].URI)
	}
}

func TestModSecEventsExposeISOTimestamp(t *testing.T) {
	s := newTestServerWithBbolt(t, "tok")
	sdb := store.Global()

	ts := time.Now().Add(-5 * time.Minute)
	if err := sdb.AppendHistory([]alert.Finding{
		modsecBlock("198.51.100.30", "site.test", "/hit", "900113", ts),
	}); err != nil {
		t.Fatal(err)
	}

	w := httptest.NewRecorder()
	s.apiModSecEvents(w, httptest.NewRequest(http.MethodGet, "/api/v1/modsec/events", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}

	var resp []modsecEventView
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v\nbody: %s", err, w.Body.String())
	}
	if len(resp) != 1 {
		t.Fatalf("events = %d, want 1", len(resp))
	}
	// The UI renders timestamps in the operator's timezone and sorts on them, so
	// each event must carry a full RFC3339 instant, not a date-less "15:04:05".
	got, err := time.Parse(time.RFC3339, resp[0].TimeISO)
	if err != nil {
		t.Fatalf("time_iso %q is not RFC3339: %v", resp[0].TimeISO, err)
	}
	if want := ts.UTC().Truncate(time.Second); !got.Equal(want) {
		t.Fatalf("time_iso = %v, want %v", got, want)
	}
	if want := ts.Format("15:04:05"); resp[0].Time != want {
		t.Fatalf("legacy time = %q, want %q", resp[0].Time, want)
	}
}

func TestModSecBlocksReadScopeAccess(t *testing.T) {
	s := newTestServerWithBbolt(t, "admin-tok")
	s.cfg.WebUI.Tokens = []config.WebUIToken{
		{Name: "admin", Token: "admin-tok", Scope: "admin"},
		{Name: "read-only", Token: "read-tok", Scope: "read"},
	}
	sdb := store.Global()
	now := time.Now()
	if err := sdb.AppendHistory([]alert.Finding{
		modsecBlock("198.51.100.10", "site.test", "/x", "900116", now),
	}); err != nil {
		t.Fatal(err)
	}

	handler := s.requireRead(http.HandlerFunc(s.apiModSecBlocks))
	req := httptest.NewRequest(http.MethodGet, "/api/v1/modsec/blocks", nil)
	req.Header.Set("Authorization", "Bearer read-tok")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("read-scope GET /api/v1/modsec/blocks status = %d, body = %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "198.51.100.10") {
		t.Errorf("response body missing seeded IP: %s", w.Body.String())
	}
}

func TestModSecBlocksReportsHistoryScanTruncation(t *testing.T) {
	s := newTestServerWithBbolt(t, "tok")
	sdb := store.Global()
	now := time.Now().Add(-time.Minute)
	findings := make([]alert.Finding, 0, modsecFindingsScanCap+1)
	for i := 0; i < modsecFindingsScanCap+1; i++ {
		findings = append(findings, modsecBlock("198.51.100.99", "site.test", "/wp-login.php", "900113", now))
	}
	if err := sdb.AppendHistory(findings); err != nil {
		t.Fatal(err)
	}

	w := httptest.NewRecorder()
	s.apiModSecBlocks(w, httptest.NewRequest(http.MethodGet, "/api/v1/modsec/blocks", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
	if got := w.Header().Get("X-CSM-Truncated"); got != "1" {
		t.Fatalf("X-CSM-Truncated = %q, want 1 when ModSec history scan cap is hit", got)
	}
}
