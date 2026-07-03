package webui

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/store"
)

func postUnban(t *testing.T, s *Server, ip string) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", strings.NewReader(`{"ip":"`+ip+`"}`))
	req.Header.Set("Content-Type", "application/json")
	s.apiFirewallUnban(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("unban %s status = %d; body=%s", ip, w.Code, w.Body.String())
	}
	return w
}

// TestAPIFirewallUnbanDropsAutoBlockThreatRow pins STO-18 on the WebUI
// unblock path: unbanning an IP must clear its auto-block threat row so
// ip_reputation stops re-flagging it, while an operator permanent block
// survives the firewall-only unban.
func TestAPIFirewallUnbanDropsAutoBlockThreatRow(t *testing.T) {
	s := newTestServerWithBbolt(t, "tok")
	t.Cleanup(checks.SetGlobalThreatDBForTest(t.TempDir()))
	s.blocker = newFullBlocker()

	tdb := checks.GetThreatDB()
	tdb.AddTemporary("203.0.113.7", "web_attack", time.Hour)
	tdb.AddPermanent("203.0.113.8", "operator block")

	postUnban(t, s, "203.0.113.7")
	if src, ok := tdb.Lookup("203.0.113.7"); ok {
		t.Fatalf("auto-block IP still flagged after unban: source=%q", src)
	}
	if _, found := store.Global().GetPermanentBlock("203.0.113.7"); found {
		t.Fatal("auto-block threat row survived unban")
	}

	postUnban(t, s, "203.0.113.8")
	if _, ok := tdb.Lookup("203.0.113.8"); !ok {
		t.Fatal("operator IP unflagged by unban")
	}
	entry, found := store.Global().GetPermanentBlock("203.0.113.8")
	if !found || entry.Source != store.ThreatSourceOperator {
		t.Fatalf("operator threat row not intact: found=%v entry=%+v", found, entry)
	}
}
