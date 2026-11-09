package webui

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/firewall"
)

func (fb *fullBlocker) UnblockSubnetIfUnchanged(expected firewall.SubnetEntry) error {
	if reason, ok := fb.subnetsBlocked[expected.CIDR]; !ok || reason != expected.Reason {
		return firewall.ErrBlockChanged
	}
	return fb.UnblockSubnet(expected.CIDR)
}

type changingSubnetBlocker struct {
	*fullBlocker
	failure error
}

func (b *changingSubnetBlocker) UnblockSubnet(cidr string) error {
	if b.failure != nil {
		return b.failure
	}
	// The operator replaced the automatic block after the handler read it.
	b.subnetsBlocked[cidr] = "operator replacement"
	return b.fullBlocker.UnblockSubnet(cidr)
}

func (b *changingSubnetBlocker) UnblockSubnetIfUnchanged(expected firewall.SubnetEntry) error {
	if b.failure != nil {
		return b.failure
	}
	b.subnetsBlocked[expected.CIDR] = "operator replacement"
	return b.fullBlocker.UnblockSubnetIfUnchanged(expected)
}

func TestUnbanReportsSubnetRemovalFailure(t *testing.T) {
	for _, mode := range []string{"operator replacement", "kernel failure", "unsupported backend"} {
		t.Run(mode, func(t *testing.T) {
			s := newTestServer(t, "")
			fb := &changingSubnetBlocker{fullBlocker: newFullBlocker()}
			if mode == "kernel failure" {
				fb.failure = errors.New("kernel unavailable")
			}
			const cidr = "203.0.113.0/24"
			fb.subnetsBlocked[cidr] = "auto-netblock"
			s.blocker = fb
			wantStatus := http.StatusInternalServerError
			if mode == "unsupported backend" {
				s.blocker = struct {
					IPBlocker
					selfUnbanner
					subnetUnblocker
				}{fb, fb, fb}
				wantStatus = http.StatusNotImplemented
			}
			dir := filepath.Join(s.cfg.StatePath, "firewall")
			if err := os.MkdirAll(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			data, err := json.Marshal(firewall.FirewallState{BlockedNet: []firewall.SubnetEntry{{CIDR: cidr, Reason: "auto-netblock", Source: firewall.SourceAutoResponse, Automatic: true}}})
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "state.json"), data, 0o600); err != nil {
				t.Fatal(err)
			}
			w := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"ip":"203.0.113.5"}`))
			req.Header.Set("Content-Type", "application/json")
			s.apiFirewallUnban(w, req)
			if _, kept := fb.subnetsBlocked[cidr]; !kept {
				t.Error("unban deleted a replacement operator block")
			}
			assertJSONError(t, mode, w, wantStatus)
			if !strings.Contains(w.Body.String(), cidr) {
				t.Errorf("response does not identify the failed subnet: %s", w.Body.String())
			}
		})
	}
}

func TestUnbanSubnetScopeThroughRouter(t *testing.T) {
	for _, scope := range []string{"admin", "unban"} {
		for _, tc := range []struct {
			ip, automatic, nested, operator, unrelated string
		}{
			{"203.0.113.5", "203.0.113.0/24", "203.0.113.0/25", "203.0.113.0/26", "192.0.2.0/24"},
			{"::ffff:203.0.113.5", "203.0.113.0/24", "203.0.113.0/25", "203.0.113.0/26", "192.0.2.0/24"},
			{"2001:db8::5", "2001:db8::/64", "2001:db8::/80", "2001:db8::/96", "2001:db8:1::/64"},
		} {
			t.Run(scope+"/"+tc.ip, func(t *testing.T) {
				s := newTestServer(t, "")
				token := randomBrowserCredential()
				addPolicyToken(s, config.WebUIToken{Name: "caller", Token: token, Scope: scope})
				fb := newFullBlocker()
				s.blocker = fb
				entries := []firewall.SubnetEntry{
					{CIDR: tc.operator, Reason: "operator deny", Source: firewall.SourceCLI},
					{CIDR: tc.automatic, Reason: "auto-netblock", Source: firewall.SourceAutoResponse, Automatic: true},
					{CIDR: tc.nested, Reason: "auto-netblock", Source: firewall.SourceAutoResponse, Automatic: true},
					{CIDR: tc.unrelated, Reason: "auto-netblock", Source: firewall.SourceAutoResponse, Automatic: true},
				}
				for _, entry := range entries {
					fb.subnetsBlocked[entry.CIDR] = entry.Reason
				}
				dir := filepath.Join(s.cfg.StatePath, "firewall")
				if err := os.MkdirAll(dir, 0o700); err != nil {
					t.Fatal(err)
				}
				data, err := json.Marshal(firewall.FirewallState{BlockedNet: entries})
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(dir, "state.json"), data, 0o600); err != nil {
					t.Fatal(err)
				}
				w := httptest.NewRecorder()
				req := httptest.NewRequest(http.MethodPost, "/api/v1/firewall/unban", strings.NewReader(`{"ip":"`+tc.ip+`"}`))
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("Authorization", "Bearer "+token)
				s.httpSrv.Handler.ServeHTTP(w, req)
				if w.Code != http.StatusOK {
					t.Fatalf("status=%d, body=%s", w.Code, w.Body.String())
				}
				var result struct {
					Removed string `json:"subnet_removed"`
					Kept    string `json:"subnet_kept"`
				}
				if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
					t.Fatal(err)
				}
				if result.Removed != tc.automatic || result.Kept != tc.operator {
					t.Errorf("subnet result = %+v", result)
				}
				if len(fb.subnetsBlocked) != 2 || fb.subnetsBlocked[tc.operator] != "operator deny" || fb.subnetsBlocked[tc.unrelated] != "auto-netblock" {
					t.Fatalf("surviving subnets = %v", fb.subnetsBlocked)
				}
				if scope == "unban" && (len(fb.unbanned) != 1 || len(fb.unblocked) != 0) {
					t.Error("panel release used operator authority")
				}
				if scope == "admin" && (len(fb.unblocked) != 1 || len(fb.unbanned) != 0) {
					t.Error("operator release used panel authority")
				}
			})
		}
	}
}

func TestUnbanKeepsUnprovenAutomaticSubnet(t *testing.T) {
	s := newTestServer(t, "")
	fb := newFullBlocker()
	const cidr = "203.0.113.0/24"
	fb.subnetsBlocked[cidr] = "manual response to auto-netblock"
	s.blocker = fb
	dir := filepath.Join(s.cfg.StatePath, "firewall")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	// Older state inferred this source from an operator's free-form reason.
	data := []byte(`{"blocked_nets":[{"cidr":"203.0.113.0/24","reason":"manual response to auto-netblock","source":"auto_response"}]}`)
	if err := os.WriteFile(filepath.Join(dir, "state.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	w := postUnban(t, s, "203.0.113.5")
	if _, kept := fb.subnetsBlocked[cidr]; !kept {
		t.Fatal("unban trusted legacy reason-derived automatic provenance")
	}
	if !strings.Contains(w.Body.String(), `"subnet_kept":"`+cidr+`"`) {
		t.Fatalf("response did not report retained subnet: %s", w.Body.String())
	}
}
