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
