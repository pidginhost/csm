package webui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/store"
)

// runBulkWhitelist issues a bulk whitelist over ips and returns the undo
// token surfaced in the response.
func runBulkWhitelist(t *testing.T, s *Server, ips []string) string {
	t.Helper()
	body, _ := json.Marshal(map[string]interface{}{"ips": ips, "action": "whitelist"})
	rec := httptest.NewRecorder()
	s.apiThreatBulkAction(rec, bearerRequest("POST", "/api/v1/threat/bulk-action", body))
	if rec.Code != http.StatusOK {
		t.Fatalf("bulk whitelist status = %d; body=%s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Count     int    `json:"count"`
		UndoToken string `json:"undo_token"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode bulk response: %v; body=%s", err, rec.Body.String())
	}
	if resp.UndoToken == "" {
		t.Fatalf("bulk whitelist returned no undo token; body=%s", rec.Body.String())
	}
	return resp.UndoToken
}

func runUndo(t *testing.T, s *Server, token string) {
	t.Helper()
	body, _ := json.Marshal(undoRunRequest{ID: token})
	rec := httptest.NewRecorder()
	s.apiUndoRun(rec, bearerRequest("POST", "/api/v1/undo/run", body))
	if rec.Code != http.StatusOK {
		t.Fatalf("undo run status = %d; body=%s", rec.Code, rec.Body.String())
	}
}

// TestUndoBulkWhitelistRestoresBlocking pins WUI-02: undoing a bulk
// whitelist must remove the firewall allow rules the whitelist added AND
// restore the threat-DB rows it removed (with source/expiry intact), or a
// mis-clicked whitelist of attackers permanently bypasses every future block.
func TestUndoBulkWhitelistRestoresBlocking(t *testing.T) {
	s := newTestServerWithBbolt(t, "tok")
	t.Cleanup(checks.SetGlobalThreatDBForTest(t.TempDir()))
	blocker := newFullBlocker()
	s.blocker = blocker

	tdb := checks.GetThreatDB()
	tdb.AddTemporary("203.0.113.7", "web_attack", time.Hour) // auto-block, expiry
	tdb.AddPermanent("203.0.113.8", "operator block")        // operator, no expiry

	token := runBulkWhitelist(t, s, []string{"203.0.113.7", "203.0.113.8"})

	// After whitelist: firewall allow rules exist and threats are gone.
	if _, ok := blocker.allowed["203.0.113.7"]; !ok {
		t.Fatal("bulk whitelist did not add a firewall allow rule")
	}
	if _, ok := tdb.Lookup("203.0.113.7"); ok {
		t.Fatal("threat row should be gone right after whitelist")
	}

	runUndo(t, s, token)

	// Firewall allow rules removed (core bug): attacker no longer bypasses blocks.
	if _, ok := blocker.allowed["203.0.113.7"]; ok {
		t.Fatal("undo left the firewall allow rule for the auto-block IP")
	}
	if _, ok := blocker.allowed["203.0.113.8"]; ok {
		t.Fatal("undo left the firewall allow rule for the operator IP")
	}

	// Whitelist entries cleared.
	if store.Global().IsWhitelisted("203.0.113.7") || store.Global().IsWhitelisted("203.0.113.8") {
		t.Fatal("undo left an IP whitelisted")
	}

	// Auto-block threat row restored with its source and expiry preserved.
	if _, ok := tdb.Lookup("203.0.113.7"); !ok {
		t.Fatal("undo did not restore the auto-block threat row")
	}
	entry, found := store.Global().GetPermanentBlock("203.0.113.7")
	if !found {
		t.Fatal("auto-block row missing from store after undo")
	}
	if entry.Source != store.ThreatSourceAutoBlock {
		t.Fatalf("restored source = %q, want autoblock", entry.Source)
	}
	if entry.ExpiresAt.IsZero() {
		t.Fatal("restored auto-block row lost its expiry (would become a permablock)")
	}

	// Operator threat row restored as a never-expiring operator block.
	if _, ok := tdb.Lookup("203.0.113.8"); !ok {
		t.Fatal("undo did not restore the operator threat row")
	}
	opEntry, found := store.Global().GetPermanentBlock("203.0.113.8")
	if !found || opEntry.Source != store.ThreatSourceOperator || !opEntry.ExpiresAt.IsZero() {
		t.Fatalf("operator row not restored faithfully: found=%v entry=%+v", found, opEntry)
	}
}
