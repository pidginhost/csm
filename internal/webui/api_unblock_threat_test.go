package webui

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

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
	tdb.AddTemporary("203.0.113.20", "web_attack", 0)
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
	tdb.AddTemporary("203.0.113.30", "web_attack", 0)
	tdb.AddTemporary("203.0.113.31", "mail_bruteforce", 0)

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
