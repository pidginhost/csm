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

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/attackdb"
	"github.com/pidginhost/csm/internal/firewall"
	"github.com/pidginhost/csm/internal/store"
)

type cappedBody struct {
	Items     []json.RawMessage `json:"items"`
	Total     *int              `json:"total"`
	Limit     int               `json:"limit"`
	Truncated *bool             `json:"truncated"`
}

func decodeCapped(t *testing.T, name string, w *httptest.ResponseRecorder) cappedBody {
	t.Helper()
	if w.Code != http.StatusOK {
		t.Fatalf("%s: status = %d, body %s", name, w.Code, w.Body.String())
	}
	var body cappedBody
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil || body.Items == nil || body.Truncated == nil {
		t.Fatalf("%s: body %s is not {items, truncated}", name, w.Body.String())
	}
	return body
}

func assertCapped(t *testing.T, name string, body cappedBody, items int, truncated bool) {
	t.Helper()
	if len(body.Items) != items || *body.Truncated != truncated {
		t.Errorf("%s: %d items, truncated %v; want %d items, truncated %v", name, len(body.Items), *body.Truncated, items, truncated)
	}
}

// A list cut to a limit says so. truncated is true when entries were left
// out and false when the list is whole, so a client knows whether to ask
// for more instead of taking a full page for everything there is.
func TestCappedListsReportTruncation(t *testing.T) {
	t.Run("ui audit", func(t *testing.T) {
		s := newTestServer(t, "tok")
		write := func(n int) {
			f, err := os.Create(filepath.Join(s.cfg.StatePath, uiAuditFile))
			if err != nil {
				t.Fatal(err)
			}
			enc := json.NewEncoder(f)
			for i := 0; i < n; i++ {
				_ = enc.Encode(UIAuditEntry{Timestamp: time.Now().Add(time.Duration(i) * time.Second), Action: "block", Target: "203.0.113.1"})
			}
			_ = f.Close()
		}
		write(uiAuditPageLimit + 1)
		w := httptest.NewRecorder()
		s.apiUIAudit(w, httptest.NewRequest("GET", "/api/v1/audit", nil))
		assertCapped(t, "audit past the limit", decodeCapped(t, "audit", w), uiAuditPageLimit, true)

		write(uiAuditPageLimit)
		w = httptest.NewRecorder()
		s.apiUIAudit(w, httptest.NewRequest("GET", "/api/v1/audit", nil))
		assertCapped(t, "audit at the limit", decodeCapped(t, "audit", w), uiAuditPageLimit, false)
	})

	t.Run("top attackers", func(t *testing.T) {
		recs := map[string]*attackdb.IPRecord{}
		for i := 1; i <= 3; i++ {
			ip := fmt.Sprintf("198.51.100.%d", i)
			recs[ip] = &attackdb.IPRecord{IP: ip, ThreatScore: 10 * i, EventCount: i}
		}
		seedAttackDB(t, recs)
		s := newTestServer(t, "tok")
		w := httptest.NewRecorder()
		s.apiThreatTopAttackers(w, httptest.NewRequest("GET", "/?limit=2", nil))
		assertCapped(t, "limit below the records", decodeCapped(t, "top attackers", w), 2, true)
		w = httptest.NewRecorder()
		s.apiThreatTopAttackers(w, httptest.NewRequest("GET", "/?limit=3", nil))
		assertCapped(t, "limit at the records", decodeCapped(t, "top attackers", w), 3, false)
	})

	t.Run("threat events", func(t *testing.T) {
		s := newTestServerWithBbolt(t, "tok")
		seedAttackDB(t, map[string]*attackdb.IPRecord{"198.51.100.7": {IP: "198.51.100.7", EventCount: 3}})
		for i := 0; i < 3; i++ {
			ev := store.AttackEvent{Timestamp: time.Now().Add(-time.Duration(i) * time.Minute), IP: "198.51.100.7", AttackType: "brute_force", CheckName: "wp_login"}
			if err := store.Global().RecordAttackEvent(ev, i); err != nil {
				t.Fatal(err)
			}
		}
		w := httptest.NewRecorder()
		s.apiThreatEvents(w, httptest.NewRequest("GET", "/?ip=198.51.100.7&limit=2", nil))
		assertCapped(t, "limit below the events", decodeCapped(t, "threat events", w), 2, true)
		w = httptest.NewRecorder()
		s.apiThreatEvents(w, httptest.NewRequest("GET", "/?ip=198.51.100.7&limit=3", nil))
		assertCapped(t, "limit at the events", decodeCapped(t, "threat events", w), 3, false)
	})

	t.Run("modsec events", func(t *testing.T) {
		s := newTestServerWithBbolt(t, "tok")
		now := time.Now()
		if err := store.Global().AppendHistory([]alert.Finding{
			modsecBlock("198.51.100.20", "site.test", "/a", "900113", now.Add(-3*time.Minute)),
			modsecBlock("198.51.100.21", "site.test", "/b", "900113", now.Add(-2*time.Minute)),
			modsecBlock("198.51.100.22", "site.test", "/c", "900113", now.Add(-1*time.Minute)),
		}); err != nil {
			t.Fatal(err)
		}
		w := httptest.NewRecorder()
		s.apiModSecEvents(w, httptest.NewRequest("GET", "/api/v1/modsec/events?limit=2", nil))
		body := decodeCapped(t, "modsec events", w)
		assertCapped(t, "limit below the events", body, 2, true)
		if body.Total == nil || *body.Total != 3 {
			t.Errorf("modsec events total = %v, want 3", body.Total)
		}
	})

	t.Run("firewall audit", func(t *testing.T) {
		s := newTestServer(t, "tok")
		var entries []firewall.AuditEntry
		for i := 0; i < 5; i++ {
			entries = append(entries, firewall.AuditEntry{Timestamp: time.Now().Add(time.Duration(i) * time.Second), Action: "block", IP: fmt.Sprintf("203.0.113.%d", i+1)})
		}
		writeFirewallAudit(t, s.cfg.StatePath, entries)
		w := httptest.NewRecorder()
		s.apiFirewallAudit(w, httptest.NewRequest("GET", "/api/v1/firewall/audit?limit=2", nil))
		body := decodeCapped(t, "firewall audit", w)
		assertCapped(t, "limit below the entries", body, 2, true)
		if body.Total == nil || *body.Total != 5 {
			t.Errorf("firewall audit total = %v, want 5", body.Total)
		}

		// limit=0 asks for the whole log.
		w = httptest.NewRecorder()
		s.apiFirewallAudit(w, httptest.NewRequest("GET", "/api/v1/firewall/audit?limit=0", nil))
		var all struct {
			Items []json.RawMessage `json:"items"`
			Total int               `json:"total"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &all); err != nil || len(all.Items) != 5 || all.Total != 5 {
			t.Errorf("limit=0 body %s, want all 5 entries", w.Body.String())
		}
	})

	// The history search stops one row past the timeline limit; hitting it
	// means older rows were never read.
	t.Run("incident timeline history", func(t *testing.T) {
		s := newTestServerWithBbolt(t, "tok")
		s.incidentCorrelator = nil
		var rows []alert.Finding
		start := time.Now().Add(-time.Hour)
		for i := 0; i <= incidentTimelineEventLimit; i++ {
			rows = append(rows, alert.Finding{Severity: alert.High, Check: "wp_login_bruteforce",
				Message: fmt.Sprintf("attempt %d from 203.0.113.9", i), Timestamp: start.Add(time.Duration(i) * time.Second)})
		}
		if err := store.Global().AppendHistory(rows); err != nil {
			t.Fatal(err)
		}
		w := httptest.NewRecorder()
		s.apiIncident(w, httptest.NewRequest("GET", "/api/v1/incident?ip=203.0.113.9", nil))
		assertCapped(t, "history past the limit", decodeCapped(t, "incident timeline", w), incidentTimelineEventLimit, true)
	})
}

// writeCapped keeps the count of every match next to the page it sends.
func TestWriteCappedKeepsTheTotal(t *testing.T) {
	w := httptest.NewRecorder()
	writeCapped(w, []int{1, 2, 3}, 7, 2, map[string]interface{}{"side": "x"})
	body := decodeCapped(t, "writeCapped", w)
	assertCapped(t, "cut page", body, 2, true)
	if body.Total == nil || *body.Total != 7 || body.Limit != 2 {
		t.Errorf("total %v limit %d, want 7 and 2", body.Total, body.Limit)
	}
	w = httptest.NewRecorder()
	writeCapped(w, []int{1, 2}, 2, 5, nil)
	assertCapped(t, "whole list", decodeCapped(t, "writeCapped", w), 2, false)
}
