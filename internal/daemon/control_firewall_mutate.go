package daemon

import (
	"encoding/json"
	"fmt"
	"net"
	"time"

	"github.com/pidginhost/csm/internal/control"
)

// Single-IP firewall mutation handlers. Each validates args, guards on
// c.d.fwEngine != nil, calls the matching engine method, and returns a
// FirewallAckResult with a human-readable message the CLI prints verbatim.

func (c *ControlListener) handleFirewallBlock(argsRaw json.RawMessage) (any, error) {
	var args control.FirewallIPArgs
	if len(argsRaw) > 0 {
		if err := json.Unmarshal(argsRaw, &args); err != nil {
			return nil, fmt.Errorf("parsing args: %w", err)
		}
	}
	if net.ParseIP(args.IP) == nil {
		return nil, fmt.Errorf("invalid ip: %q", args.IP)
	}
	if c.d.fwEngine == nil {
		return nil, fmt.Errorf("firewall disabled in csm.yaml")
	}
	reason := args.Reason
	if reason == "" {
		reason = "Blocked via CLI"
	}
	if err := c.d.fwEngine.BlockIP(args.IP, reason, 0); err != nil {
		return nil, fmt.Errorf("block %s: %w", args.IP, err)
	}
	return control.FirewallAckResult{Message: fmt.Sprintf("Blocked %s - %s", args.IP, reason)}, nil
}

func (c *ControlListener) handleFirewallUnblock(argsRaw json.RawMessage) (any, error) {
	var args control.FirewallIPArgs
	if len(argsRaw) > 0 {
		if err := json.Unmarshal(argsRaw, &args); err != nil {
			return nil, fmt.Errorf("parsing args: %w", err)
		}
	}
	if net.ParseIP(args.IP) == nil {
		return nil, fmt.Errorf("invalid ip: %q", args.IP)
	}
	if c.d.fwEngine == nil {
		return nil, fmt.Errorf("firewall disabled in csm.yaml")
	}
	if err := c.d.fwEngine.UnblockIP(args.IP); err != nil {
		return nil, fmt.Errorf("unblock %s: %w", args.IP, err)
	}
	return control.FirewallAckResult{Message: fmt.Sprintf("Unblocked %s", args.IP)}, nil
}

func (c *ControlListener) handleFirewallAllow(argsRaw json.RawMessage) (any, error) {
	var args control.FirewallIPArgs
	if len(argsRaw) > 0 {
		if err := json.Unmarshal(argsRaw, &args); err != nil {
			return nil, fmt.Errorf("parsing args: %w", err)
		}
	}
	if net.ParseIP(args.IP) == nil {
		return nil, fmt.Errorf("invalid ip: %q", args.IP)
	}
	if c.d.fwEngine == nil {
		return nil, fmt.Errorf("firewall disabled in csm.yaml")
	}
	reason := args.Reason
	if reason == "" {
		reason = "Allowed via CLI"
	}
	if err := c.d.fwEngine.AllowIP(args.IP, reason); err != nil {
		return nil, fmt.Errorf("allow %s: %w", args.IP, err)
	}
	return control.FirewallAckResult{Message: fmt.Sprintf("Allowed %s - %s", args.IP, reason)}, nil
}

func (c *ControlListener) handleFirewallRemoveAllow(argsRaw json.RawMessage) (any, error) {
	var args control.FirewallIPArgs
	if len(argsRaw) > 0 {
		if err := json.Unmarshal(argsRaw, &args); err != nil {
			return nil, fmt.Errorf("parsing args: %w", err)
		}
	}
	if net.ParseIP(args.IP) == nil {
		return nil, fmt.Errorf("invalid ip: %q", args.IP)
	}
	if c.d.fwEngine == nil {
		return nil, fmt.Errorf("firewall disabled in csm.yaml")
	}
	if err := c.d.fwEngine.RemoveAllowIP(args.IP); err != nil {
		return nil, fmt.Errorf("remove-allow %s: %w", args.IP, err)
	}
	return control.FirewallAckResult{Message: fmt.Sprintf("Removed %s from allow list", args.IP)}, nil
}

func (c *ControlListener) handleFirewallAllowPort(argsRaw json.RawMessage) (any, error) {
	var args control.FirewallPortArgs
	if len(argsRaw) > 0 {
		if err := json.Unmarshal(argsRaw, &args); err != nil {
			return nil, fmt.Errorf("parsing args: %w", err)
		}
	}
	if net.ParseIP(args.IP) == nil {
		return nil, fmt.Errorf("invalid ip: %q", args.IP)
	}
	if args.Port <= 0 || args.Port > 65535 {
		return nil, fmt.Errorf("invalid port: %d", args.Port)
	}
	proto := args.Proto
	if proto == "" {
		proto = "tcp"
	}
	if proto != "tcp" && proto != "udp" {
		return nil, fmt.Errorf("invalid proto: %q (want tcp or udp)", args.Proto)
	}
	if c.d.fwEngine == nil {
		return nil, fmt.Errorf("firewall disabled in csm.yaml")
	}
	reason := args.Reason
	if reason == "" {
		reason = "Port-allowed via CLI"
	}
	if err := c.d.fwEngine.AllowIPPort(args.IP, args.Port, proto, reason); err != nil {
		return nil, fmt.Errorf("allow-port %s %s:%d: %w", args.IP, proto, args.Port, err)
	}
	return control.FirewallAckResult{
		Message: fmt.Sprintf("Allowed %s on %s:%d - %s", args.IP, proto, args.Port, reason),
	}, nil
}

func (c *ControlListener) handleFirewallRemovePort(argsRaw json.RawMessage) (any, error) {
	var args control.FirewallPortArgs
	if len(argsRaw) > 0 {
		if err := json.Unmarshal(argsRaw, &args); err != nil {
			return nil, fmt.Errorf("parsing args: %w", err)
		}
	}
	if net.ParseIP(args.IP) == nil {
		return nil, fmt.Errorf("invalid ip: %q", args.IP)
	}
	if args.Port <= 0 || args.Port > 65535 {
		return nil, fmt.Errorf("invalid port: %d", args.Port)
	}
	proto := args.Proto
	if proto == "" {
		proto = "tcp"
	}
	if proto != "tcp" && proto != "udp" {
		return nil, fmt.Errorf("invalid proto: %q (want tcp or udp)", args.Proto)
	}
	if c.d.fwEngine == nil {
		return nil, fmt.Errorf("firewall disabled in csm.yaml")
	}
	if err := c.d.fwEngine.RemoveAllowIPPort(args.IP, args.Port, proto); err != nil {
		return nil, fmt.Errorf("remove-port %s %s:%d: %w", args.IP, proto, args.Port, err)
	}
	return control.FirewallAckResult{
		Message: fmt.Sprintf("Removed port-allow for %s on %s:%d", args.IP, proto, args.Port),
	}, nil
}

func (c *ControlListener) handleFirewallTempBan(argsRaw json.RawMessage) (any, error) {
	var args control.FirewallIPArgs
	if len(argsRaw) > 0 {
		if err := json.Unmarshal(argsRaw, &args); err != nil {
			return nil, fmt.Errorf("parsing args: %w", err)
		}
	}
	// Parse timeout FIRST so callers get a duration-parse error before
	// the engine-nil check (the unit test depends on this ordering).
	if args.Timeout == "" {
		return nil, fmt.Errorf("tempban requires timeout")
	}
	timeout, err := time.ParseDuration(args.Timeout)
	if err != nil {
		return nil, fmt.Errorf("parsing duration %q: %w", args.Timeout, err)
	}
	if net.ParseIP(args.IP) == nil {
		return nil, fmt.Errorf("invalid ip: %q", args.IP)
	}
	if c.d.fwEngine == nil {
		return nil, fmt.Errorf("firewall disabled in csm.yaml")
	}
	reason := args.Reason
	if reason == "" {
		reason = "Temp-banned via CLI"
	}
	if err := c.d.fwEngine.BlockIP(args.IP, reason, timeout); err != nil {
		return nil, fmt.Errorf("tempban %s: %w", args.IP, err)
	}
	return control.FirewallAckResult{
		Message: fmt.Sprintf("Temp-banned %s for %s - %s", args.IP, timeout, reason),
	}, nil
}

func (c *ControlListener) handleFirewallTempAllow(argsRaw json.RawMessage) (any, error) {
	var args control.FirewallIPArgs
	if len(argsRaw) > 0 {
		if err := json.Unmarshal(argsRaw, &args); err != nil {
			return nil, fmt.Errorf("parsing args: %w", err)
		}
	}
	if args.Timeout == "" {
		return nil, fmt.Errorf("tempallow requires timeout")
	}
	timeout, err := time.ParseDuration(args.Timeout)
	if err != nil {
		return nil, fmt.Errorf("parsing duration %q: %w", args.Timeout, err)
	}
	if net.ParseIP(args.IP) == nil {
		return nil, fmt.Errorf("invalid ip: %q", args.IP)
	}
	if c.d.fwEngine == nil {
		return nil, fmt.Errorf("firewall disabled in csm.yaml")
	}
	reason := args.Reason
	if reason == "" {
		reason = "Temp-allowed via CLI"
	}
	if err := c.d.fwEngine.TempAllowIP(args.IP, reason, timeout); err != nil {
		return nil, fmt.Errorf("tempallow %s: %w", args.IP, err)
	}
	return control.FirewallAckResult{
		Message: fmt.Sprintf("Temp-allowed %s for %s - %s", args.IP, timeout, reason),
	}, nil
}
