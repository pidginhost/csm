package webui

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/firewall"
)

func writeFirewallAudit(t *testing.T, statePath string, entries []firewall.AuditEntry) {
	t.Helper()
	dir := filepath.Join(statePath, "firewall")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	var data []byte
	for _, e := range entries {
		line, err := json.Marshal(e)
		if err != nil {
			t.Fatal(err)
		}
		data = append(append(data, line...), '\n')
	}
	if err := os.WriteFile(filepath.Join(dir, "audit.jsonl"), data, 0o600); err != nil {
		t.Fatal(err)
	}
}

// Audit times are instants, so the page can show them in the operator's
// time zone. A server-local wall clock without a zone cannot be converted.
func TestFirewallAuditTimestampsAreInstants(t *testing.T) {
	s := newTestServer(t, "tok")
	zone := time.FixedZone("server", 3*3600)
	writeFirewallAudit(t, s.cfg.StatePath, []firewall.AuditEntry{{
		Timestamp: time.Date(2026, 9, 23, 3, 0, 0, 0, zone), Action: "block", IP: "203.0.113.77", Source: "auto_block",
	}})
	w := httptest.NewRecorder()
	s.apiFirewallAudit(w, httptest.NewRequest(http.MethodGet, "/api/v1/firewall/audit?limit=5", nil))
	var got []struct {
		Timestamp string `json:"timestamp"`
	}
	decodeItems(t, w.Body.Bytes(), &got)
	if len(got) != 1 || got[0].Timestamp != "2026-09-23T00:00:00Z" {
		t.Fatalf("timestamps = %+v, want RFC 3339 UTC", got)
	}
}

// Filters apply to the whole log and the limit to what they matched: a
// search for an address blocked before the last page of entries must find it.
func TestFirewallAuditSearchReachesOlderEntries(t *testing.T) {
	s := newTestServer(t, "tok")
	start := time.Now().Add(-time.Hour)
	entries := []firewall.AuditEntry{{Timestamp: start, Action: "block", IP: "203.0.113.77", Reason: "brute force", Source: "auto_block"}}
	for i := 0; i < 200; i++ {
		entries = append(entries, firewall.AuditEntry{
			Timestamp: start.Add(time.Duration(i+1) * time.Second),
			Action:    "block",
			IP:        fmt.Sprintf("198.51.100.%d", i%250),
			Reason:    "scanner",
			Source:    "auto_block",
		})
	}
	writeFirewallAudit(t, s.cfg.StatePath, entries)

	w := httptest.NewRecorder()
	s.apiFirewallAudit(w, httptest.NewRequest(http.MethodGet, "/api/v1/firewall/audit?limit=50&search=203.0.113.77", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", w.Code, w.Body.String())
	}
	var got []struct {
		IP string `json:"ip"`
	}
	decodeItems(t, w.Body.Bytes(), &got)
	if len(got) != 1 || got[0].IP != "203.0.113.77" {
		t.Fatalf("search returned %+v, want the older block", got)
	}

	// Without a filter the limit still returns the newest entries.
	w = httptest.NewRecorder()
	s.apiFirewallAudit(w, httptest.NewRequest(http.MethodGet, "/api/v1/firewall/audit?limit=50", nil))
	got = nil
	decodeItems(t, w.Body.Bytes(), &got)
	if len(got) != 50 {
		t.Fatalf("unfiltered page = %d entries, want 50", len(got))
	}
	for _, e := range got {
		if e.IP == "203.0.113.77" {
			t.Fatal("the oldest entry should not be on the newest page")
		}
	}
}
