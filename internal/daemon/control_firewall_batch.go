package daemon

import (
	"encoding/json"
	"fmt"
)

// Subnet / batch / meta firewall handlers: operations that either span
// multiple IPs (deny-file/allow-file, subnet ops) or reshape the whole
// ruleset (flush/restart/apply-confirmed/confirm). Bodies land in Task
// 6 of the phase-2 plan. `restart` and `apply-confirmed` will require a
// live fwEngine — a dead engine means "systemctl restart csm" rather
// than rebuild-from-handler.

func (c *ControlListener) handleFirewallDenySubnet(_ json.RawMessage) (any, error) {
	return nil, fmt.Errorf("not implemented")
}

func (c *ControlListener) handleFirewallRemoveSubnet(_ json.RawMessage) (any, error) {
	return nil, fmt.Errorf("not implemented")
}

func (c *ControlListener) handleFirewallDenyFile(_ json.RawMessage) (any, error) {
	return nil, fmt.Errorf("not implemented")
}

func (c *ControlListener) handleFirewallAllowFile(_ json.RawMessage) (any, error) {
	return nil, fmt.Errorf("not implemented")
}

func (c *ControlListener) handleFirewallFlush(_ json.RawMessage) (any, error) {
	return nil, fmt.Errorf("not implemented")
}

func (c *ControlListener) handleFirewallRestart(_ json.RawMessage) (any, error) {
	return nil, fmt.Errorf("not implemented")
}

func (c *ControlListener) handleFirewallApplyConfirmed(_ json.RawMessage) (any, error) {
	return nil, fmt.Errorf("not implemented")
}

func (c *ControlListener) handleFirewallConfirm(_ json.RawMessage) (any, error) {
	return nil, fmt.Errorf("not implemented")
}
