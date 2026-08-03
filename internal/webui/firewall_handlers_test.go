package webui

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/checks"
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

func assertJSONErrorResponse(t *testing.T, w *httptest.ResponseRecorder, code int, message string) {
	t.Helper()
	if w.Code != code {
		t.Fatalf("status = %d, want %d; body=%s", w.Code, code, w.Body.String())
	}
	if got := w.Header().Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", got)
	}
	var body map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode error response: %v; body=%s", err, w.Body.String())
	}
	if len(body) != 1 || body["error"] != message {
		t.Errorf("error body = %#v, want map[error:%q]", body, message)
	}
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

func TestAPIFirewallAllowIPInvalidDurationRejected(t *testing.T) {
	s := newTestServerWithFirewall(t, "tok")
	blocker := newFullBlocker()
	s.blocker = blocker
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", strings.NewReader(`{"ip":"203.0.113.5","duration":"1w"}`))
	req.Header.Set("Content-Type", "application/json")
	s.apiFirewallAllowIP(w, req)
	assertJSONErrorResponse(t, w, http.StatusBadRequest, `invalid duration "1w"`)
	if len(blocker.allowed) != 0 {
		t.Errorf("invalid request changed allow rules: %#v", blocker.allowed)
	}
}

func TestAPIBlockIPInvalidDurationRejected(t *testing.T) {
	s := newTestServerWithFirewall(t, "tok")
	blocker := newFullBlocker()
	s.blocker = blocker
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", strings.NewReader(`{"ip":"203.0.113.5","duration":"24 hours"}`))
	req.Header.Set("Content-Type", "application/json")
	s.apiBlockIP(w, req)
	assertJSONErrorResponse(t, w, http.StatusBadRequest, `invalid duration "24 hours"`)
	if len(blocker.blocked) != 0 {
		t.Errorf("invalid request changed block rules: %#v", blocker.blocked)
	}
}

func TestAPIFirewallDenySubnetInvalidDurationRejected(t *testing.T) {
	s := newTestServerWithFirewall(t, "tok")
	blocker := newFullBlocker()
	s.blocker = blocker
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", strings.NewReader(`{"cidr":"203.0.113.0/24","duration":"forever"}`))
	req.Header.Set("Content-Type", "application/json")
	s.apiFirewallDenySubnet(w, req)
	assertJSONErrorResponse(t, w, http.StatusBadRequest, `invalid duration "forever"`)
	if len(blocker.subnetsBlocked) != 0 {
		t.Errorf("invalid request changed subnet rules: %#v", blocker.subnetsBlocked)
	}
}

type cfCoveredBlocker struct{ *fullBlocker }

func (b cfCoveredBlocker) CloudflareCovers(string) bool { return true }

// Blocking an IP inside a Cloudflare allow range is a silent no-op on
// 80/443, so the response must carry a warning the UI can show.
func TestAPIBlockIPWarnsWhenCloudflareCovered(t *testing.T) {
	s := newTestServerWithFirewall(t, "tok")
	s.blocker = cfCoveredBlocker{newFullBlocker()}
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", strings.NewReader(`{"ip":"203.0.113.50"}`))
	req.Header.Set("Content-Type", "application/json")
	s.apiBlockIP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("block = %d, body %s", w.Code, w.Body.String())
	}
	var body map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(body["warning"], "Cloudflare") {
		t.Errorf("body = %v, want a Cloudflare coverage warning", body)
	}
}

func TestAPIBlockIPNoWarningWithoutCloudflareCoverage(t *testing.T) {
	s := newTestServerWithFirewall(t, "tok")
	s.blocker = newFullBlocker()
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", strings.NewReader(`{"ip":"203.0.113.51"}`))
	req.Header.Set("Content-Type", "application/json")
	s.apiBlockIP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("block = %d, body %s", w.Code, w.Body.String())
	}
	var body map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if _, ok := body["warning"]; ok {
		t.Errorf("body = %v, want no warning field", body)
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

// A web UI flush must clear the auto-block tracker and ThreatDB rows the
// same way the single-IP unblock path does; otherwise the next scan
// re-blocks every flushed IP from its surviving threat row.
func TestAPIFirewallFlushClearsAutoBlockState(t *testing.T) {
	s := newTestServerWithFirewall(t, "tok")
	restore := checks.SetGlobalThreatDBForTest(t.TempDir())
	t.Cleanup(restore)

	fwDir := filepath.Join(s.cfg.StatePath, "firewall")
	if err := os.MkdirAll(fwDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fwDir, "state.json"),
		[]byte(`{"blocked":[{"ip":"203.0.113.30","reason":"r"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(s.cfg.StatePath, "blocked_ips.json"),
		[]byte(`{"ips":[{"ip":"203.0.113.30","expires_at":"2099-01-01T00:00:00Z"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	checks.GetThreatDB().AddTemporary("203.0.113.30", "r", time.Hour)

	s.blocker = newFullBlocker()
	w := httptest.NewRecorder()
	s.apiFirewallFlush(w, httptest.NewRequest("POST", "/", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("flush = %d, body %s", w.Code, w.Body.String())
	}

	data, err := os.ReadFile(filepath.Join(s.cfg.StatePath, "blocked_ips.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "203.0.113.30") {
		t.Errorf("blocked_ips.json still tracks flushed IP: %s", data)
	}
	if _, found := checks.GetThreatDB().Lookup("203.0.113.30"); found {
		t.Error("threat row survived web UI flush; next scan would re-block")
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
