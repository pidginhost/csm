package webui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/store"
)

// TestAPIUnblockIPDropsAutoBlockThreatRow pins STO-18 on the /api/v1/unblock-ip
// path: unblocking must clear the IP's auto-block threat row so ip_reputation
// stops re-flagging it, while operator rows survive a firewall-only unblock.
func TestAPIUnblockIPDropsAutoBlockThreatRow(t *testing.T) {
	s := newTestServerWithBbolt(t, "tok")
	t.Cleanup(checks.SetGlobalThreatDBForTest(t.TempDir()))
	s.blocker = newFullBlocker()

	tdb := checks.GetThreatDB()
	tdb.AddTemporary("203.0.113.20", "web_attack", time.Hour)
	tdb.AddPermanent("203.0.113.21", "operator block")

	for _, ip := range []string{"203.0.113.20", "203.0.113.21"} {
		w := httptest.NewRecorder()
		req := httptest.NewRequest("POST", "/", strings.NewReader(`{"ip":"`+ip+`"}`))
		req.Header.Set("Content-Type", "application/json")
		s.apiUnblockIP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("unblock %s status = %d; body=%s", ip, w.Code, w.Body.String())
		}
	}

	if src, ok := tdb.Lookup("203.0.113.20"); ok {
		t.Fatalf("auto-block IP still flagged after unblock: source=%q", src)
	}
	if _, found := store.Global().GetPermanentBlock("203.0.113.20"); found {
		t.Fatal("auto-block threat row survived unblock")
	}
	entry, found := store.Global().GetPermanentBlock("203.0.113.21")
	if !found || entry.Source != store.ThreatSourceOperator {
		t.Fatalf("operator threat row not intact: found=%v entry=%+v", found, entry)
	}
}

// TestAPIUnblockBulkDropsAutoBlockThreatRows pins the same contract on the
// /api/v1/unblock-bulk path.
func TestAPIUnblockBulkDropsAutoBlockThreatRows(t *testing.T) {
	s := newTestServerWithBbolt(t, "tok")
	t.Cleanup(checks.SetGlobalThreatDBForTest(t.TempDir()))
	s.blocker = newFullBlocker()

	tdb := checks.GetThreatDB()
	tdb.AddTemporary("203.0.113.30", "web_attack", time.Hour)
	tdb.AddTemporary("203.0.113.31", "mail_bruteforce", time.Hour)

	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/",
		strings.NewReader(`{"ips":["203.0.113.30","203.0.113.31"]}`))
	req.Header.Set("Content-Type", "application/json")
	s.apiUnblockBulk(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("bulk unblock status = %d; body=%s", w.Code, w.Body.String())
	}

	for _, ip := range []string{"203.0.113.30", "203.0.113.31"} {
		if _, ok := tdb.Lookup(ip); ok {
			t.Fatalf("auto-block IP %s still flagged after bulk unblock", ip)
		}
		if _, found := store.Global().GetPermanentBlock(ip); found {
			t.Fatalf("auto-block threat row for %s survived bulk unblock", ip)
		}
	}
}

func TestAPIUnblockBulkUndoRestoresAutoBlockThreatRows(t *testing.T) {
	s := newTestServerWithBbolt(t, "tok")
	t.Cleanup(checks.SetGlobalThreatDBForTest(t.TempDir()))
	blocker := newFullBlocker()
	s.blocker = blocker

	ip := "203.0.113.32"
	tdb := checks.GetThreatDB()
	tdb.AddTemporary(ip, "web_attack", time.Hour)
	blocker.blocked[ip] = "web_attack"

	body, _ := json.Marshal(map[string]interface{}{
		"ips": []string{ip},
	})
	w := httptest.NewRecorder()
	s.apiUnblockBulk(w, bearerRequest("POST", "/api/v1/unblock-bulk", body))
	if w.Code != http.StatusOK {
		t.Fatalf("bulk unblock status = %d; body=%s", w.Code, w.Body.String())
	}
	var resp struct {
		UndoToken string `json:"undo_token"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v; body=%s", err, w.Body.String())
	}
	if resp.UndoToken == "" {
		t.Fatalf("bulk unblock returned no undo token; body=%s", w.Body.String())
	}
	if _, ok := tdb.Lookup(ip); ok {
		t.Fatal("auto-block IP still flagged after bulk unblock")
	}
	if _, found := store.Global().GetPermanentBlock(ip); found {
		t.Fatal("auto-block threat row survived bulk unblock")
	}

	runUndo(t, s, resp.UndoToken)

	if _, ok := blocker.blocked[ip]; !ok {
		t.Fatal("undo did not re-block the IP in the firewall")
	}
	if _, ok := tdb.Lookup(ip); !ok {
		t.Fatal("undo did not restore the auto-block threat row")
	}
	entry, found := store.Global().GetPermanentBlock(ip)
	if !found {
		t.Fatal("auto-block row missing from store after undo")
	}
	if entry.Source != store.ThreatSourceAutoBlock {
		t.Fatalf("restored source = %q, want autoblock", entry.Source)
	}
	if entry.ExpiresAt.IsZero() {
		t.Fatal("restored auto-block row lost its expiry")
	}
}
