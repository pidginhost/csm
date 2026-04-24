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
