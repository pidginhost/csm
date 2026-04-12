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
