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

	var raw struct {
		Entries json.RawMessage `json:"entries"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &raw); err != nil {
		t.Fatalf("unmarshal: %v\nbody: %s", err, w.Body.String())
	}
	if string(raw.Entries) != "[]" {
		t.Errorf("entries raw = %s, want []", raw.Entries)
	}
}
