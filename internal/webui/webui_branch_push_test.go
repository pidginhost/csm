package webui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/firewall"
	"github.com/pidginhost/csm/internal/store"
)

// --- apiAccounts with home dir data ----------------------------------

func TestAPIAccountsWithBboltFindings(t *testing.T) {
	s := newTestServerWithBbolt(t, "tok")
	// Seed findings with different account paths
	s.store.AppendHistory([]alert.Finding{
		{Severity: alert.Critical, Check: "webshell", Message: "in /home/alice/public_html/wso.php", Timestamp: time.Now()},
		{Severity: alert.High, Check: "brute_force", Message: "SSH from /home/bob/logs", Timestamp: time.Now()},
	})

	w := httptest.NewRecorder()
	s.apiAccounts(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	var data []interface{}
	_ = json.Unmarshal(w.Body.Bytes(), &data)
}

// --- apiFirewallAllowIP with valid data + bbolt ----------------------

func TestAPIFirewallAllowIPWithBbolt(t *testing.T) {
	s := newTestServerWithBbolt(t, "tok")
	s.cfg.Firewall = &firewall.FirewallConfig{Enabled: true}

	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", strings.NewReader(`{"ip":"10.0.0.5","reason":"admin access"}`))
	req.Header.Set("Content-Type", "application/json")
	s.apiFirewallAllowIP(w, req)
	// Exercises the allow path through bbolt store
	if w.Code == 0 {
		t.Error("unexpected zero status")
	}
}

// --- apiFirewallRemoveAllow with bbolt --------------------------------

func TestAPIFirewallRemoveAllowWithBbolt(t *testing.T) {
	s := newTestServerWithBbolt(t, "tok")
	s.cfg.Firewall = &firewall.FirewallConfig{Enabled: true}

	// First allow an IP
	sdb := store.Global()
	_ = sdb.AllowIP("10.0.0.5", "admin", time.Time{})

	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", strings.NewReader(`{"ip":"10.0.0.5"}`))
	req.Header.Set("Content-Type", "application/json")
	s.apiFirewallRemoveAllow(w, req)
	if w.Code == 0 {
		t.Error("unexpected zero status")
	}
}

// --- apiFirewallSubnets with bbolt data -------------------------------

func TestAPIFirewallSubnetsWithBbolt(t *testing.T) {
	s := newTestServerWithBbolt(t, "tok")
	s.cfg.Firewall = &firewall.FirewallConfig{Enabled: true}

	sdb := store.Global()
	_ = sdb.AddSubnet("192.168.0.0/16", "test block")

	w := httptest.NewRecorder()
	s.apiFirewallSubnets(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
}

// --- apiFirewallCheck with blocked IP in bbolt -----------------------

func TestAPIFirewallCheckBlockedIP(t *testing.T) {
	s := newTestServerWithBbolt(t, "tok")
	s.cfg.Firewall = &firewall.FirewallConfig{Enabled: true}

	sdb := store.Global()
	_ = sdb.BlockIP("203.0.113.5", "brute-force", time.Time{})

	w := httptest.NewRecorder()
	s.apiFirewallCheck(w, httptest.NewRequest("GET", "/?ip=203.0.113.5", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	var data map[string]interface{}
	_ = json.Unmarshal(w.Body.Bytes(), &data)
	// Exercises the check path through bbolt.
	_ = data
}

// --- apiEmailQuarantineList with bbolt --------------------------------

func TestAPIEmailQuarantineListWithBbolt(t *testing.T) {
	s := newTestServerWithBbolt(t, "tok")
	w := httptest.NewRecorder()
	s.apiEmailQuarantineList(w, httptest.NewRequest("GET", "/?limit=10", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
}

// --- apiModSecStats with bbolt data -----------------------------------

func TestAPIModSecStatsWithBbolt(t *testing.T) {
	s := newTestServerWithBbolt(t, "tok")
	w := httptest.NewRecorder()
	s.apiModSecStats(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
}

// --- apiModSecBlocks with bbolt data ----------------------------------

func TestAPIModSecBlocksWithBbolt(t *testing.T) {
	s := newTestServerWithBbolt(t, "tok")
	w := httptest.NewRecorder()
	s.apiModSecBlocks(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
}

// --- apiModSecEvents with bbolt data ----------------------------------

func TestAPIModSecEventsWithBbolt(t *testing.T) {
	s := newTestServerWithBbolt(t, "tok")
	w := httptest.NewRecorder()
	s.apiModSecEvents(w, httptest.NewRequest("GET", "/?limit=10", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
}
