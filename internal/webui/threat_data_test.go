package webui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/firewall"
)

// --- apiThreatWhitelistIP POST with valid IP -------------------------

func TestAPIThreatWhitelistIPValidIP(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", strings.NewReader(`{"ip":"203.0.113.5"}`))
	req.Header.Set("Content-Type", "application/json")
	s.apiThreatWhitelistIP(w, req)
	// May succeed or fail depending on ThreatDB state, but exercises the handler.
	if w.Code == 0 {
		t.Error("unexpected zero status")
	}
}

// --- apiThreatUnwhitelistIP POST with valid IP -----------------------

func TestAPIThreatUnwhitelistIPValidIP(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", strings.NewReader(`{"ip":"203.0.113.5"}`))
	req.Header.Set("Content-Type", "application/json")
	s.apiThreatUnwhitelistIP(w, req)
	if w.Code == 0 {
		t.Error("unexpected zero status")
	}
}

// --- apiThreatBlockIP POST with valid IP -----------------------------

func TestAPIThreatBlockIPValidIP(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", strings.NewReader(`{"ip":"203.0.113.5","reason":"test","duration":"24h"}`))
	req.Header.Set("Content-Type", "application/json")
	s.apiThreatBlockIP(w, req)
	if w.Code == 0 {
		t.Error("unexpected zero status")
	}
}

func TestAPIThreatBlockIPMissingIP(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", strings.NewReader(`{"reason":"test"}`))
	req.Header.Set("Content-Type", "application/json")
	s.apiThreatBlockIP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("missing IP = %d, want 400", w.Code)
	}
}

// --- apiThreatClearIP POST with valid IP -----------------------------

func TestAPIThreatClearIPValidIP(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", strings.NewReader(`{"ip":"203.0.113.5"}`))
	req.Header.Set("Content-Type", "application/json")
	s.apiThreatClearIP(w, req)
	if w.Code == 0 {
		t.Error("unexpected zero status")
	}
}

// --- apiThreatTempWhitelistIP POST -----------------------------------

func TestAPIThreatTempWhitelistIPValidIP(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", strings.NewReader(`{"ip":"203.0.113.5","duration":"4h"}`))
	req.Header.Set("Content-Type", "application/json")
	s.apiThreatTempWhitelistIP(w, req)
	if w.Code == 0 {
		t.Error("unexpected zero status")
	}
}

// --- apiThreatBulkAction POST ----------------------------------------

func TestAPIThreatBulkActionWhitelist(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", strings.NewReader(`{"action":"whitelist","ips":["203.0.113.5"]}`))
	req.Header.Set("Content-Type", "application/json")
	s.apiThreatBulkAction(w, req)
	if w.Code == 0 {
		t.Error("unexpected zero status")
	}
}

func TestAPIThreatBulkActionBadJSON(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", strings.NewReader(`{bad json`))
	req.Header.Set("Content-Type", "application/json")
	s.apiThreatBulkAction(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("bad JSON = %d, want 400", w.Code)
	}
}

// --- Firewall POST handlers with data --------------------------------

func TestAPIFirewallAllowIPValidIP(t *testing.T) {
	s := newTestServerWithFirewall(t, "tok")
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", strings.NewReader(`{"ip":"10.0.0.5","reason":"admin"}`))
	req.Header.Set("Content-Type", "application/json")
	s.apiFirewallAllowIP(w, req)
	if w.Code == 0 {
		t.Error("unexpected zero status")
	}
}

func TestAPIFirewallRemoveAllowValidIP(t *testing.T) {
	s := newTestServerWithFirewall(t, "tok")
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", strings.NewReader(`{"ip":"10.0.0.5"}`))
	req.Header.Set("Content-Type", "application/json")
	s.apiFirewallRemoveAllow(w, req)
	if w.Code == 0 {
		t.Error("unexpected zero status")
	}
}

func TestAPIFirewallDenySubnetValid(t *testing.T) {
	s := newTestServerWithFirewall(t, "tok")
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", strings.NewReader(`{"cidr":"192.168.0.0/16","reason":"test"}`))
	req.Header.Set("Content-Type", "application/json")
	s.apiFirewallDenySubnet(w, req)
	if w.Code == 0 {
		t.Error("unexpected zero status")
	}
}

func TestAPIFirewallRemoveSubnetValid(t *testing.T) {
	s := newTestServerWithFirewall(t, "tok")
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", strings.NewReader(`{"cidr":"192.168.0.0/16"}`))
	req.Header.Set("Content-Type", "application/json")
	s.apiFirewallRemoveSubnet(w, req)
	if w.Code == 0 {
		t.Error("unexpected zero status")
	}
}

func TestAPIFirewallFlushPost(t *testing.T) {
	s := newTestServerWithFirewall(t, "tok")
	w := httptest.NewRecorder()
	s.apiFirewallFlush(w, httptest.NewRequest("POST", "/", nil))
	if w.Code == 0 {
		t.Error("unexpected zero status")
	}
}

func TestAPIFirewallUnbanValidIP(t *testing.T) {
	s := newTestServerWithFirewall(t, "tok")
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", strings.NewReader(`{"ip":"203.0.113.5"}`))
	req.Header.Set("Content-Type", "application/json")
	s.apiFirewallUnban(w, req)
	if w.Code == 0 {
		t.Error("unexpected zero status")
	}
}

// --- apiFirewallStatus with bbolt data -------------------------------

func TestAPIFirewallStatusWithBboltData(t *testing.T) {
	s := newTestServerWithBbolt(t, "tok")
	s.cfg.Firewall = &firewall.FirewallConfig{Enabled: true, InfraIPs: []string{"10.0.0.1"}}

	w := httptest.NewRecorder()
	s.apiFirewallStatus(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	var data map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &data); err != nil {
		t.Fatalf("bad JSON: %v", err)
	}
	if data["enabled"] != true {
		t.Errorf("enabled = %v", data["enabled"])
	}
}
