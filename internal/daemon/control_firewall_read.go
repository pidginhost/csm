package daemon

import (
	"encoding/json"
	"fmt"
)

// Read-only firewall handlers: no state mutation, just surface what
// firewall.LoadState already has. Bodies land in Task 4 of the phase-2
// plan; stubs here keep the dispatcher from falling through.

func (c *ControlListener) handleFirewallStatus(_ json.RawMessage) (any, error) {
	return nil, fmt.Errorf("not implemented")
}

func (c *ControlListener) handleFirewallPorts(_ json.RawMessage) (any, error) {
	return nil, fmt.Errorf("not implemented")
}

func (c *ControlListener) handleFirewallGrep(_ json.RawMessage) (any, error) {
	return nil, fmt.Errorf("not implemented")
}

func (c *ControlListener) handleFirewallAudit(_ json.RawMessage) (any, error) {
	return nil, fmt.Errorf("not implemented")
}
