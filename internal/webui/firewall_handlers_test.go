package webui

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/firewall"
	"github.com/pidginhost/csm/internal/platform"
)

func newTestServerWithFirewall(t *testing.T, token string) *Server {
	t.Helper()
	s := newTestServer(t, token)
	s.cfg.Firewall = &firewall.FirewallConfig{Enabled: true}
	return s
}

func withCPanelPlatform(t *testing.T) {
	t.Helper()
	platform.ResetForTest()
	panel := platform.PanelCPanel
	if !platform.SetOverrides(platform.Overrides{Panel: &panel}) {
		t.Fatal("platform override must install before Detect")
	}
	t.Cleanup(platform.ResetForTest)
}

func withFirewallCheckCommand(t *testing.T, fn func(context.Context, string, ...string) ([]byte, error)) {
	t.Helper()
	prev := firewallCheckCommandOutput
	firewallCheckCommandOutput = fn
	t.Cleanup(func() { firewallCheckCommandOutput = prev })
}

func decodeFirewallCheckBody(t *testing.T, w *httptest.ResponseRecorder) map[string]interface{} {
	t.Helper()
	var body map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v; body=%s", err, w.Body.String())
	}
	return body
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

func TestAPIFirewallCheckReportsCphulkTempBan(t *testing.T) {
	withCPanelPlatform(t)

	var calls []string
	withFirewallCheckCommand(t, func(ctx context.Context, name string, args ...string) ([]byte, error) {
		if err := ctx.Err(); err != nil {
			t.Fatalf("command context already done: %v", err)
		}
		calls = append(calls, name+" "+strings.Join(args, " "))
		if name != "nft" {
			t.Fatalf("temp-ban hit should not call %s with args %v", name, args)
		}
		want := []string{"get", "element", "inet", "filter", "cphulk-TempBan", "{", "86.121.184.44", "}"}
		if !reflect.DeepEqual(args, want) {
			t.Fatalf("nft args = %v, want %v", args, want)
		}
		return []byte("element exists"), nil
	})

	s := newTestServerWithFirewall(t, "tok")
	w := httptest.NewRecorder()
	s.apiFirewallCheck(w, httptest.NewRequest("GET", "/?ip=86.121.184.44", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	body := decodeFirewallCheckBody(t, w)
	if body["cphulk"] != true {
		t.Fatalf("cphulk = %v, want true; body=%v", body["cphulk"], body)
	}
	if len(calls) != 1 {
		t.Fatalf("commands = %v, want one nft lookup", calls)
	}
}

func TestAPIFirewallCheckCphulkTempBanUsesExactElementLookup(t *testing.T) {
	withCPanelPlatform(t)

	withFirewallCheckCommand(t, func(_ context.Context, name string, args ...string) ([]byte, error) {
		switch name {
		case "nft":
			want := []string{"get", "element", "inet", "filter", "cphulk-TempBan", "{", "10.20.30.4", "}"}
			if !reflect.DeepEqual(args, want) {
				t.Fatalf("nft args = %v, want %v", args, want)
			}
			return nil, errors.New("element not found")
		case "whmapi1":
			return []byte(`{"data":{"records":[]}}`), nil
		default:
			t.Fatalf("unexpected command %s %v", name, args)
			return nil, errors.New("unexpected command")
		}
	})

	s := newTestServerWithFirewall(t, "tok")
	w := httptest.NewRecorder()
	s.apiFirewallCheck(w, httptest.NewRequest("GET", "/?ip=10.20.30.4", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	body := decodeFirewallCheckBody(t, w)
	if body["cphulk"] != false {
		t.Fatalf("cphulk = %v, want false for absent prefix IP; body=%v", body["cphulk"], body)
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

func TestCphulkTempBanLookupIP(t *testing.T) {
	got, ok := cphulkTempBanLookupIP("::ffff:86.121.184.44")
	if !ok {
		t.Fatal("IPv4-mapped address should be accepted")
	}
	if got != "86.121.184.44" {
		t.Fatalf("lookup IP = %q, want canonical IPv4", got)
	}
	if _, ok := cphulkTempBanLookupIP("not-an-ip"); ok {
		t.Fatal("invalid address should not be accepted")
	}
}
