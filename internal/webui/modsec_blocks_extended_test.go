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
	if len(resp) != 1 {
		t.Fatalf("got %d block rows, want 1", len(resp))
	}

	row := resp[0]
	if row.Hits != 4 {
		t.Errorf("Hits = %d, want 4", row.Hits)
	}
	if row.DomainCount != 2 {
		t.Errorf("DomainCount = %d, want 2 (example.com + shop.example.com)", row.DomainCount)
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
