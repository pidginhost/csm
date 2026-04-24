package daemon

import (
	"encoding/json"
	"fmt"
)

// Single-IP firewall mutation handlers. Bodies land in Task 5 of the
// phase-2 plan. Each will validate args, check c.d.fwEngine != nil, and
// call the matching engine method.

func (c *ControlListener) handleFirewallBlock(_ json.RawMessage) (any, error) {
	return nil, fmt.Errorf("not implemented")
}

func (c *ControlListener) handleFirewallUnblock(_ json.RawMessage) (any, error) {
	return nil, fmt.Errorf("not implemented")
}

func (c *ControlListener) handleFirewallAllow(_ json.RawMessage) (any, error) {
	return nil, fmt.Errorf("not implemented")
}

func (c *ControlListener) handleFirewallAllowPort(_ json.RawMessage) (any, error) {
	return nil, fmt.Errorf("not implemented")
}

func (c *ControlListener) handleFirewallRemovePort(_ json.RawMessage) (any, error) {
	return nil, fmt.Errorf("not implemented")
}

func (c *ControlListener) handleFirewallTempBan(_ json.RawMessage) (any, error) {
	return nil, fmt.Errorf("not implemented")
}

func (c *ControlListener) handleFirewallTempAllow(_ json.RawMessage) (any, error) {
	return nil, fmt.Errorf("not implemented")
}
