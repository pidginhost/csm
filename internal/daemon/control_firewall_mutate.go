package daemon

import (
	"encoding/json"
	"fmt"
	"net"
	"time"

	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/control"
	"github.com/pidginhost/csm/internal/firewall"
	"github.com/pidginhost/csm/internal/store"
)

// dropAutoBlockThreatRow removes the auto-block threat row for ip after an
// operator unblock. Operator permanent blocks are left in place: a
// firewall-only unblock must not silently clear a deliberate block. Under
// older builds a stale auto-block row could outlive the firewall block and
// ip_reputation would re-flag the IP into a new block loop. Clearing the
// persisted row when present and the in-memory temp copy stops that.
func dropAutoBlockThreatRow(ip string) {
	if sdb := store.Global(); sdb != nil {
		_, _ = sdb.RemoveAutoBlock(ip)
	}
	if tdb := checks.GetThreatDB(); tdb != nil {
		tdb.RemoveTemporary(ip)
	}
}

// Single-IP firewall mutation handlers. Each validates args, guards on
// c.d.fwEngine != nil, calls the matching engine method, and returns a
// FirewallAckResult with a human-readable message the CLI prints verbatim.

// operatorForceBlock runs an operator-initiated force block and reports it
// to the shared firewall outcome metric alongside auto-response blocks.
func operatorForceBlock(e interface {
	BlockIPForce(ip string, reason string, timeout time.Duration) error
}, ip, reason string, timeout time.Duration) error {
	err := e.BlockIPForce(ip, reason, timeout)
	checks.ObserveOperatorBlock(err, checks.BlockSourceCLI)
	return err
}

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
	// Operator-initiated: bypass auto_response.dry_run gate.
	if err := operatorForceBlock(c.d.fwEngine, args.IP, reason, 0); err != nil {
		return nil, fmt.Errorf("block %s: %w", args.IP, err)
	}
	msg := fmt.Sprintf("Blocked %s - %s", args.IP, reason)
	msg += cloudflareCoverageSuffix(c.d.fwEngine, args.IP)
	return control.FirewallAckResult{Message: msg}, nil
}

// cloudflareCoverageSuffix warns the operator when a just-blocked IP sits
// inside a Cloudflare allow range: the input chain accepts CF edges on TCP
// 80/443 before the blocked drop, so the block does not stop web traffic.
func cloudflareCoverageSuffix(e interface{ CloudflareCovers(string) bool }, ip string) string {
	if e != nil && e.CloudflareCovers(ip) {
		return " (warning: " + firewall.CloudflareCoverageWarning + ")"
	}
	return ""
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
	dropAutoBlockThreatRow(args.IP)
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
	msg := fmt.Sprintf("Allowed %s - %s", args.IP, reason)
	if cidr, covered := c.d.fwEngine.BlockedSubnetCovering(args.IP); covered {
		msg += fmt.Sprintf(" (WARNING: still dropped by blocked subnet %s; unblock the subnet for this allow to take effect)", cidr)
	}
	return control.FirewallAckResult{Message: msg}, nil
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
	// Operator-initiated: bypass auto_response.dry_run gate.
	if err := operatorForceBlock(c.d.fwEngine, args.IP, reason, timeout); err != nil {
		return nil, fmt.Errorf("tempban %s: %w", args.IP, err)
	}
	msg := fmt.Sprintf("Temp-banned %s for %s - %s", args.IP, timeout, reason)
	msg += cloudflareCoverageSuffix(c.d.fwEngine, args.IP)
	return control.FirewallAckResult{Message: msg}, nil
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
