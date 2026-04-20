package webui

import (
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/attackdb"
)

// seedAttackDB installs a test attack database populated with `recs`.
// The global is restored to nil on test cleanup so parallel suites
// inside the same test binary stay isolated.
func seedAttackDB(t *testing.T, recs map[string]*attackdb.IPRecord) {
	t.Helper()
	attackdb.SetGlobal(attackdb.NewForTest(recs))
	t.Cleanup(func() { attackdb.SetGlobal(nil) })
}

// --- apiThreatTopAttackers with live attackdb -------------------------

// The handler with an initialized attackdb must return JSON that
// enriches each record with the unified-score/verdict shape, sorted
// by threat score descending.
func TestAPIThreatTopAttackersReturnsEnrichedRecords(t *testing.T) {
	now := time.Now()
	seedAttackDB(t, map[string]*attackdb.IPRecord{
		"198.51.100.10": {
			IP:          "198.51.100.10",
			ThreatScore: 90,
			EventCount:  20,
			FirstSeen:   now.Add(-time.Hour),
			LastSeen:    now,
		},
		"198.51.100.20": {
			IP:          "198.51.100.20",
			ThreatScore: 60,
			EventCount:  5,
			FirstSeen:   now.Add(-30 * time.Minute),
			LastSeen:    now,
		},
	})

	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	s.apiThreatTopAttackers(w, httptest.NewRequest("GET", "/?limit=50", nil))
	if w.Code != 200 {
		t.Fatalf("status: %d", w.Code)
	}
	var results []map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &results); err != nil {
		t.Fatalf("decode body: %v (body=%s)", err, w.Body.String())
	}
	if len(results) != 2 {
		t.Fatalf("expected 2 records, got %d: %+v", len(results), results)
	}
	// Sort is by threat_score DESC: 90 then 60.
	if score0, _ := results[0]["threat_score"].(float64); int(score0) != 90 {
		t.Errorf("first record threat_score: got %v, want 90", results[0]["threat_score"])
	}
	if score1, _ := results[1]["threat_score"].(float64); int(score1) != 60 {
		t.Errorf("second record threat_score: got %v, want 60", results[1]["threat_score"])
	}
	// Enrichment fields must be present in the JSON shape.
	for _, key := range []string{"unified_score", "verdict", "abuse_score", "in_threat_db", "currently_blocked"} {
		if _, ok := results[0][key]; !ok {
			t.Errorf("expected enrichment field %q in response", key)
		}
	}
}

// --- apiThreatEvents with live attackdb -------------------------------

// With an initialized attackdb and no events for the queried IP,
// the handler must return [] (empty JSON array), not null.
func TestAPIThreatEventsEmptyArrayForUnknownIP(t *testing.T) {
	seedAttackDB(t, map[string]*attackdb.IPRecord{
		"198.51.100.30": {IP: "198.51.100.30", ThreatScore: 50, EventCount: 1},
	})

	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	s.apiThreatEvents(w, httptest.NewRequest("GET", "/?ip=198.51.100.99", nil))
	if w.Code != 200 {
		t.Fatalf("status: %d", w.Code)
	}
	// Expect "[]\n" or "[]"; must not be "null".
	body := w.Body.String()
	if body == "null\n" || body == "null" {
		t.Errorf("unknown-IP response must be [], got %q", body)
	}
}

// --- apiThreatDBStats reports attack_db block when globals are live ---

// With the attack DB global initialized, the response must include the
// `attack_db` key with total_ips + top_line. The nil-DB branch stays
// covered by the existing TestAPIThreatDBStatsWithStateInitializedFinalCoverage.
func TestAPIThreatDBStatsIncludesAttackDB(t *testing.T) {
	seedAttackDB(t, map[string]*attackdb.IPRecord{
		"198.51.100.40": {IP: "198.51.100.40", ThreatScore: 75, EventCount: 3},
	})

	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	s.apiThreatDBStats(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != 200 {
		t.Fatalf("status: %d", w.Code)
	}
	var out map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v (body=%s)", err, w.Body.String())
	}
	adb, ok := out["attack_db"].(map[string]any)
	if !ok {
		t.Fatalf("expected attack_db key, got %+v", out)
	}
	if total, _ := adb["total_ips"].(float64); int(total) != 1 {
		t.Errorf("total_ips: got %v, want 1", adb["total_ips"])
	}
}

// --- apiThreatStats with initialized attackdb ------------------------

// Without attackdb the handler returns an error payload; with it
// initialized the handler returns the Stats() map.
func TestAPIThreatStatsReturnsStatsWhenInitialized(t *testing.T) {
	seedAttackDB(t, map[string]*attackdb.IPRecord{
		"198.51.100.50": {IP: "198.51.100.50", ThreatScore: 80, EventCount: 6},
	})

	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	s.apiThreatStats(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != 200 {
		t.Fatalf("status: %d", w.Code)
	}
	var out map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v (body=%s)", err, w.Body.String())
	}
	// Error branch sets {"error": "..."}; success path returns a
	// different shape (total IPs, etc.). Either way the response must
	// not carry the "error" key when attackdb is live.
	if _, hasErr := out["error"]; hasErr {
		t.Errorf("expected stats payload, got error response: %+v", out)
	}
}
