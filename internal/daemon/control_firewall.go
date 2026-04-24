package daemon

import (
	"encoding/json"
	"fmt"
)

// Firewall handlers are stubs in phase-2 Task 2. They are wired into
// dispatch so the command names exist; the real bodies land in Tasks
// 4-6 of the plan. Until then every stub fails loudly rather than
// silently succeeding so a premature caller notices immediately.

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
