package webui

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/firewall"
)

func newTestServerWithFirewall(t *testing.T, token string) *Server {
	t.Helper()
	s := newTestServer(t, token)
	s.cfg.Firewall = &firewall.FirewallConfig{Enabled: true}
	return s
}

// --- apiFirewallStatus ------------------------------------------------

func TestAPIFirewallStatusReturnsJSON(t *testing.T) {
	s := newTestServerWithFirewall(t, "tok")
	w := httptest.NewRecorder()
	s.apiFirewallStatus(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
}

// --- apiFirewallAllowed -----------------------------------------------

func TestAPIFirewallAllowedReturnsJSON(t *testing.T) {
	s := newTestServerWithFirewall(t, "tok")
	w := httptest.NewRecorder()
	s.apiFirewallAllowed(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
}

// --- apiFirewallAllowIP (POST validation) ----------------------------

func TestAPIFirewallAllowIPGetRejected(t *testing.T) {
	s := newTestServerWithFirewall(t, "tok")
	w := httptest.NewRecorder()
	s.apiFirewallAllowIP(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET allow = %d, want 405", w.Code)
	}
}

func TestAPIFirewallAllowIPMissingIP(t *testing.T) {
	s := newTestServerWithFirewall(t, "tok")
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	s.apiFirewallAllowIP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("missing IP = %d, want 400", w.Code)
	}
}

// --- apiFirewallRemoveAllow (POST validation) ------------------------

func TestAPIFirewallRemoveAllowGetRejected(t *testing.T) {
	s := newTestServerWithFirewall(t, "tok")
	w := httptest.NewRecorder()
	s.apiFirewallRemoveAllow(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET remove-allow = %d, want 405", w.Code)
	}
}

// --- apiFirewallAudit ------------------------------------------------

func TestAPIFirewallAuditReturnsJSON(t *testing.T) {
	s := newTestServerWithFirewall(t, "tok")
	w := httptest.NewRecorder()
	s.apiFirewallAudit(w, httptest.NewRequest("GET", "/?limit=10", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
}

// --- apiFirewallSubnets -----------------------------------------------

func TestAPIFirewallSubnetsReturnsJSON(t *testing.T) {
	s := newTestServerWithFirewall(t, "tok")
	w := httptest.NewRecorder()
	s.apiFirewallSubnets(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
}

// --- apiFirewallDenySubnet (POST validation) -------------------------

func TestAPIFirewallDenySubnetGetRejected(t *testing.T) {
	s := newTestServerWithFirewall(t, "tok")
	w := httptest.NewRecorder()
	s.apiFirewallDenySubnet(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET deny-subnet = %d, want 405", w.Code)
	}
}

// --- apiFirewallRemoveSubnet (POST validation) -----------------------

func TestAPIFirewallRemoveSubnetGetRejected(t *testing.T) {
	s := newTestServerWithFirewall(t, "tok")
	w := httptest.NewRecorder()
	s.apiFirewallRemoveSubnet(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET remove-subnet = %d, want 405", w.Code)
	}
}

// --- apiFirewallFlush (POST validation) ------------------------------

func TestAPIFirewallFlushGetRejected(t *testing.T) {
	s := newTestServerWithFirewall(t, "tok")
	w := httptest.NewRecorder()
	s.apiFirewallFlush(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET flush = %d, want 405", w.Code)
	}
}

// --- apiFirewallCheck ------------------------------------------------

func TestAPIFirewallCheckMissingIP(t *testing.T) {
	s := newTestServerWithFirewall(t, "tok")
	w := httptest.NewRecorder()
	s.apiFirewallCheck(w, httptest.NewRequest("GET", "/", nil))
	// Returns 200 with success=false rather than 400.
	if w.Code != http.StatusOK {
		t.Errorf("missing IP = %d, want 200", w.Code)
	}
	if !strings.Contains(w.Body.String(), "false") {
		t.Error("expected success=false in body")
	}
}

func TestAPIFirewallCheckValidIP(t *testing.T) {
	s := newTestServerWithFirewall(t, "tok")
	w := httptest.NewRecorder()
	s.apiFirewallCheck(w, httptest.NewRequest("GET", "/?ip=203.0.113.5", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
}

// --- apiFirewallUnban (POST validation) ------------------------------

func TestAPIFirewallUnbanGetRejected(t *testing.T) {
	s := newTestServerWithFirewall(t, "tok")
	w := httptest.NewRecorder()
	s.apiFirewallUnban(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET unban = %d, want 405", w.Code)
	}
}

func TestCphulkBlocksIPMatchesRecordIPOnly(t *testing.T) {
	out := []byte(`{"data":{"records":[{"ip":"10.20.30.40","type":"black"}]}}`)
	if !cphulkBlocksIP(out, "10.20.30.40") {
		t.Error("exact blocked IP must match")
	}
	if cphulkBlocksIP(out, "10.20.30.4") {
		t.Error("prefix of a blocked IP must NOT match (blocklist info leak)")
	}
	if cphulkBlocksIP(out, "1.2.3.4") {
		t.Error("unrelated IP must not match")
	}
	commentOnly := []byte(`{"data":{"records":[{"ip":"192.0.2.10","comment":"10.20.30.40"}]}}`)
	if cphulkBlocksIP(commentOnly, "10.20.30.40") {
		t.Error("IP in a non-IP record field must not match")
	}
	cidrOnly := []byte(`{"data":{"records":[{"ip":"10.20.30.40/32","type":"black"}]}}`)
	if cphulkBlocksIP(cidrOnly, "10.20.30.40") {
		t.Error("CIDR value must not match a single-IP query")
	}
	metadataOnly := []byte(`{"metadata":{"ip":"10.20.30.40"},"data":{"records":[]}}`)
	if cphulkBlocksIP(metadataOnly, "10.20.30.40") {
		t.Error("IP outside cPHulk records must not match")
	}
	if cphulkBlocksIP([]byte("not json"), "10.20.30.40") {
		t.Error("garbage output must not match")
	}
}

func TestCphulkTempBanContainsIP(t *testing.T) {
	// cPHulk brute-force temp bans live in this nftables set, not in the
	// read_cphulk_records black list. The Inspect IP check must read the set or
	// it reports "cPHulk: No" for an IP that is actively firewall-dropped.
	set := []byte(`table inet filter {
	set cphulk-TempBan {
		type ipv4_addr
		flags timeout
		elements = { 86.121.184.44 expires 15h48m46s793ms,
			     87.106.53.29 expires 10m23s653ms,
			     10.20.30.40 expires 1h2m }
	}
}`)
	if !cphulkTempBanContainsIP(set, "86.121.184.44") {
		t.Error("temp-banned IP must match")
	}
	if !cphulkTempBanContainsIP(set, "10.20.30.40") {
		t.Error("last element in the set must match")
	}
	if cphulkTempBanContainsIP(set, "6.121.184.44") {
		t.Error("suffix of a banned IP must NOT match (digit boundary)")
	}
	if cphulkTempBanContainsIP(set, "10.20.30.4") {
		t.Error("prefix of a banned IP must NOT match (digit boundary)")
	}
	if cphulkTempBanContainsIP(set, "203.0.113.9") {
		t.Error("IP absent from the set must not match")
	}
	if cphulkTempBanContainsIP(set, "") {
		t.Error("empty IP must not match")
	}
	if cphulkTempBanContainsIP(nil, "86.121.184.44") {
		t.Error("empty set output must not match")
	}
}
