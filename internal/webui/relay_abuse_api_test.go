package webui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

// Realtime php-relay findings land in persisted history, not LatestFindings;
// the endpoint must read them back via SearchHistorySince and split the
// "host:/path" ScriptKey into separate site/script columns for the panel.
func TestRelayAbuseServesFanoutFromHistory(t *testing.T) {
	s := newTestServerWithBbolt(t, "tok")
	now := time.Now()
	s.store.AppendHistory([]alert.Finding{
		{
			Check:      "email_php_relay_abuse",
			Severity:   alert.High,
			Path:       "fanout",
			SourceIP:   "192.0.2.10",
			CPUser:     "alice",
			Timestamp:  now.Add(-1 * time.Minute),
			RelayTotal: 3,
			RelayBreakdown: []alert.RelayScriptHit{
				{ScriptKey: "a.example.com:/wp-comments-post.php", Hits: 2, LastSeen: now, SampleSubject: "You won"},
				{ScriptKey: "missingcolonkey", Hits: 1, LastSeen: now},
			},
		},
		// Unrelated finding must be filtered out by the check predicate.
		{
			Check:     "waf",
			Severity:  alert.Warning,
			SourceIP:  "198.51.100.5",
			Timestamp: now.Add(-2 * time.Minute),
		},
	})

	w := httptest.NewRecorder()
	s.apiEmailRelayAbuse(w, httptest.NewRequest(http.MethodGet, "/api/v1/email/relay-abuse?limit=20", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}

	var resp relayAbuseResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v\nbody: %s", err, w.Body.String())
	}
	if len(resp.Entries) != 1 {
		t.Fatalf("entries = %d, want 1 (waf excluded): %+v", len(resp.Entries), resp.Entries)
	}

	e := resp.Entries[0]
	if e.Path != "fanout" {
		t.Errorf("path = %q, want fanout", e.Path)
	}
	if e.PathLabel != "Spam outbreak (IP fanout)" {
		t.Errorf("path_label = %q", e.PathLabel)
	}
	if e.TriggerCount != 3 {
		t.Errorf("trigger_count = %d, want 3", e.TriggerCount)
	}
	if len(e.Sites) != 2 {
		t.Fatalf("sites = %d, want 2: %+v", len(e.Sites), e.Sites)
	}
	if e.Sites[0].Site != "a.example.com" || e.Sites[0].Script != "/wp-comments-post.php" {
		t.Errorf("site[0] = %q/%q, want a.example.com//wp-comments-post.php", e.Sites[0].Site, e.Sites[0].Script)
	}
	if e.Sites[1].Site != "" || e.Sites[1].Script != "missingcolonkey" {
		t.Errorf("site[1] = %q/%q, want \"\"/missingcolonkey", e.Sites[1].Site, e.Sites[1].Script)
	}
}

// An empty store must serialize Entries as [] (non-nil) so the UI never has to
// guard against a JSON null.
func TestRelayAbuseEmptyStoreReturnsEmptySlice(t *testing.T) {
	s := newTestServerWithBbolt(t, "tok")
	w := httptest.NewRecorder()
	s.apiEmailRelayAbuse(w, httptest.NewRequest(http.MethodGet, "/api/v1/email/relay-abuse", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}

	assertEmptyItems(t, w.Body.Bytes())
}

// splitScriptKey must split on the ":/" boundary, not the first colon, so a
// host:port or IPv6-literal host stays intact.
func TestSplitScriptKey(t *testing.T) {
	cases := []struct{ in, site, script string }{
		{"a.example.com:/wp-comments-post.php", "a.example.com", "/wp-comments-post.php"},
		{"example.com:8080:/x.php", "example.com:8080", "/x.php"},
		{"host:/", "host", "/"},
		{"missingcolonkey", "", "missingcolonkey"},
		{"", "", ""},
	}
	for _, c := range cases {
		site, script := splitScriptKey(c.in)
		if site != c.site || script != c.script {
			t.Errorf("splitScriptKey(%q) = (%q, %q), want (%q, %q)", c.in, site, script, c.site, c.script)
		}
	}
}

// With only to, the range is the 24 h before it, as on the other email
// range endpoints.
func TestRelayAbuseOneSidedTo(t *testing.T) {
	s := newTestServerWithBbolt(t, "tok")
	at := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	s.store.AppendHistory([]alert.Finding{
		{Check: "email_php_relay_abuse", Severity: alert.High, Path: "volume", Timestamp: at.Add(-time.Hour)},
		{Check: "email_php_relay_abuse", Severity: alert.High, Path: "volume", Timestamp: at.Add(-25 * time.Hour)},
	})

	w := httptest.NewRecorder()
	s.apiEmailRelayAbuse(w, httptest.NewRequest(http.MethodGet, "/api/v1/email/relay-abuse?to=2026-10-20T12:00:00Z", nil))
	var resp relayAbuseResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil || w.Code != http.StatusOK {
		t.Fatalf("status %d, %v: %s", w.Code, err, w.Body.String())
	}
	if !resp.From.Equal(at.Add(-24*time.Hour)) || !resp.To.Equal(at) || resp.Total != 1 {
		t.Errorf("range %v .. %v with %d events, want the 24 h before %v with 1 event", resp.From, resp.To, resp.Total, at)
	}
}

// As for the senders count: requests in the same minute share one history
// walk; the limit still keys its own result.
func TestRelayAbuseMemoSharedWithinMinute(t *testing.T) {
	s := newTestServerWithBbolt(t, "tok")
	at := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	relay := func(ts time.Time) alert.Finding {
		return alert.Finding{Check: "email_php_relay_abuse", Severity: alert.High, Path: "volume", Timestamp: ts}
	}
	s.store.AppendHistory([]alert.Finding{relay(at.Add(-time.Hour))})
	total := func(query string) int {
		t.Helper()
		w := httptest.NewRecorder()
		s.apiEmailRelayAbuse(w, httptest.NewRequest(http.MethodGet, "/api/v1/email/relay-abuse?from=2026-10-20T10:00:00Z&"+query, nil))
		var resp relayAbuseResponse
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil || w.Code != http.StatusOK {
			t.Fatalf("status %d, %v: %s", w.Code, err, w.Body.String())
		}
		return resp.Total
	}
	if n := total("limit=20&to=2026-10-20T12:00:10Z"); n != 1 {
		t.Fatalf("total = %d, want 1", n)
	}
	s.store.AppendHistory([]alert.Finding{relay(at.Add(-30 * time.Minute))})
	if n := total("limit=20&to=2026-10-20T12:00:40Z"); n != 1 {
		t.Errorf("same minute: total = %d, want the shared 1", n)
	}
	if n := total("limit=5&to=2026-10-20T12:00:40Z"); n != 2 {
		t.Errorf("same minute, other limit: total = %d, want 2", n)
	}
	if n := total("limit=20&to=2026-10-20T12:01:05Z"); n != 2 {
		t.Errorf("next minute: total = %d, want 2", n)
	}
}
