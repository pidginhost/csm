package daemon

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/control"
)

func TestHandleFirewallStatusReturnsLiveState(t *testing.T) {
	// Use the simpler in-memory harness. cfg is zero-value so
	// cfg.Firewall is nil and cfg.StatePath is "" — LoadState tolerates
	// the missing state directory and returns an empty state.
	c := newListenerForTest(t)
	raw, err := c.handleFirewallStatus(nil)
	if err != nil {
		t.Fatalf("handleFirewallStatus: %v", err)
	}
	r := raw.(control.FirewallStatusResult)
	if r.Enabled {
		t.Errorf("Enabled=true on harness daemon; expected false")
	}
}

func TestHandleFirewallGrepDoesNotMatchNonexistent(t *testing.T) {
	c := newListenerForTest(t)
	argsJSON, _ := json.Marshal(control.FirewallGrepArgs{Pattern: "nonexistent-pattern"})
	raw, err := c.handleFirewallGrep(argsJSON)
	if err != nil {
		t.Fatalf("handleFirewallGrep: %v", err)
	}
	r := raw.(control.FirewallListResult)
	for _, line := range r.Lines {
		if strings.Contains(line, "nonexistent-pattern") {
			t.Errorf("did not expect matches, got %q", line)
		}
	}
}

func TestHandleFirewallBlockRejectsInvalidIP(t *testing.T) {
	// Validation runs before the engine check, so nil fwEngine is fine.
	c := newListenerForTest(t)
	argsJSON, _ := json.Marshal(control.FirewallIPArgs{IP: "not-an-ip"})
	_, err := c.handleFirewallBlock(argsJSON)
	if err == nil || !strings.Contains(err.Error(), "invalid ip") {
		t.Errorf("want invalid-ip error, got %v", err)
	}
}

func TestHandleFirewallBlockErrorsWhenEngineNil(t *testing.T) {
	c := newListenerForTest(t) // fwEngine is nil
	argsJSON, _ := json.Marshal(control.FirewallIPArgs{IP: "1.2.3.4"})
	_, err := c.handleFirewallBlock(argsJSON)
	if err == nil || !strings.Contains(err.Error(), "firewall disabled") {
		t.Errorf("want 'firewall disabled' error, got %v", err)
	}
}

func TestHandleFirewallTempBanParsesTimeout(t *testing.T) {
	c := newListenerForTest(t)
	// Engine is nil, so we expect the "firewall disabled" error — but
	// only after the timeout string parses. An invalid duration should
	// error before we reach the engine check.
	argsJSON, _ := json.Marshal(control.FirewallIPArgs{
		IP: "1.2.3.4", Timeout: "garbage",
	})
	_, err := c.handleFirewallTempBan(argsJSON)
	if err == nil || !strings.Contains(err.Error(), "duration") {
		t.Errorf("want duration-parse error, got %v", err)
	}
}

func TestHandleFirewallDenySubnetRejectsInvalidCIDR(t *testing.T) {
	c := newListenerForTest(t)
	argsJSON, _ := json.Marshal(control.FirewallSubnetArgs{CIDR: "not-a-cidr"})
	_, err := c.handleFirewallDenySubnet(argsJSON)
	if err == nil || !strings.Contains(err.Error(), "invalid cidr") {
		t.Errorf("want invalid-cidr error, got %v", err)
	}
}

func TestHandleFirewallDenyFileBatchSkipsInvalids(t *testing.T) {
	// Engine is nil so the handler errors before calling BlockIP. We're
	// checking the early arg-shape path: empty IPs should be rejected,
	// a mix of valid/invalid would be counted — but nil engine stops
	// actual work. So just validate the "no IPs" rejection here.
	c := newListenerForTest(t)
	argsJSON, _ := json.Marshal(control.FirewallFileArgs{IPs: nil})
	_, err := c.handleFirewallDenyFile(argsJSON)
	if err == nil || !strings.Contains(err.Error(), "no ips") {
		t.Errorf("want no-ips error, got %v", err)
	}
}

func TestHandleFirewallRestartErrorsWhenEngineNil(t *testing.T) {
	c := newListenerForTest(t)
	_, err := c.handleFirewallRestart(nil)
	if err == nil || !strings.Contains(err.Error(), "engine not running") {
		t.Errorf("want engine-not-running error, got %v", err)
	}
}

func TestHandleFirewallConfirmNoPending(t *testing.T) {
	c := newListenerForTest(t)
	c.d.cfg.StatePath = t.TempDir()
	raw, err := c.handleFirewallConfirm(nil)
	if err != nil {
		t.Fatalf("handleFirewallConfirm: %v", err)
	}
	r := raw.(control.FirewallAckResult)
	if !strings.Contains(r.Message, "No pending") {
		t.Errorf("expected 'No pending' message, got %q", r.Message)
	}
}
