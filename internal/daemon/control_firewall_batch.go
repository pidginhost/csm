package daemon

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/pidginhost/csm/internal/control"
	"github.com/pidginhost/csm/internal/firewall"
	"github.com/pidginhost/csm/internal/obs"
)

// Subnet / batch / meta firewall handlers: operations that either span
// multiple IPs (deny-file/allow-file, subnet ops) or reshape the whole
// ruleset (flush/restart/apply-confirmed/confirm). `restart` and
// `apply-confirmed` require a live fwEngine — a dead engine means
// "systemctl restart csm" rather than rebuild-from-handler.

func (c *ControlListener) handleFirewallDenySubnet(argsRaw json.RawMessage) (any, error) {
	var args control.FirewallSubnetArgs
	if len(argsRaw) > 0 {
		if err := json.Unmarshal(argsRaw, &args); err != nil {
			return nil, fmt.Errorf("parsing args: %w", err)
		}
	}
	if _, _, err := net.ParseCIDR(args.CIDR); err != nil {
		return nil, fmt.Errorf("invalid cidr: %q", args.CIDR)
	}
	if c.d.fwEngine == nil {
		return nil, fmt.Errorf("firewall disabled in csm.yaml")
	}
	reason := args.Reason
	if reason == "" {
		reason = "Blocked via CLI"
	}
	if err := c.d.fwEngine.BlockSubnet(args.CIDR, reason, 0); err != nil {
		return nil, fmt.Errorf("block subnet %s: %w", args.CIDR, err)
	}
	return control.FirewallAckResult{
		Message: fmt.Sprintf("Blocked subnet %s - %s", args.CIDR, reason),
	}, nil
}

func (c *ControlListener) handleFirewallRemoveSubnet(argsRaw json.RawMessage) (any, error) {
	var args control.FirewallSubnetArgs
	if len(argsRaw) > 0 {
		if err := json.Unmarshal(argsRaw, &args); err != nil {
			return nil, fmt.Errorf("parsing args: %w", err)
		}
	}
	if _, _, err := net.ParseCIDR(args.CIDR); err != nil {
		return nil, fmt.Errorf("invalid cidr: %q", args.CIDR)
	}
	if c.d.fwEngine == nil {
		return nil, fmt.Errorf("firewall disabled in csm.yaml")
	}
	if err := c.d.fwEngine.UnblockSubnet(args.CIDR); err != nil {
		return nil, fmt.Errorf("remove subnet %s: %w", args.CIDR, err)
	}
	return control.FirewallAckResult{
		Message: fmt.Sprintf("Removed subnet block %s", args.CIDR),
	}, nil
}

func (c *ControlListener) handleFirewallDenyFile(argsRaw json.RawMessage) (any, error) {
	var args control.FirewallFileArgs
	if len(argsRaw) > 0 {
		if err := json.Unmarshal(argsRaw, &args); err != nil {
			return nil, fmt.Errorf("parsing args: %w", err)
		}
	}
	if len(args.IPs) == 0 {
		return nil, fmt.Errorf("no ips in batch")
	}
	if c.d.fwEngine == nil {
		return nil, fmt.Errorf("firewall disabled in csm.yaml")
	}
	reason := args.Reason
	if reason == "" {
		reason = "Bulk block via CLI"
	}
	blocked, failed, skipped := 0, 0, 0
	for _, ip := range args.IPs {
		if net.ParseIP(ip) == nil {
			skipped++
			continue
		}
		if err := c.d.fwEngine.BlockIP(ip, reason, 0); err != nil {
			failed++
			continue
		}
		blocked++
	}
	msg := fmt.Sprintf("Blocked %d, skipped %d invalid", blocked, skipped)
	if failed > 0 {
		msg = fmt.Sprintf("Blocked %d, failed %d, skipped %d invalid", blocked, failed, skipped)
	}
	return control.FirewallAckResult{Message: msg}, nil
}

func (c *ControlListener) handleFirewallAllowFile(argsRaw json.RawMessage) (any, error) {
	var args control.FirewallFileArgs
	if len(argsRaw) > 0 {
		if err := json.Unmarshal(argsRaw, &args); err != nil {
			return nil, fmt.Errorf("parsing args: %w", err)
		}
	}
	if len(args.IPs) == 0 {
		return nil, fmt.Errorf("no ips in batch")
	}
	if c.d.fwEngine == nil {
		return nil, fmt.Errorf("firewall disabled in csm.yaml")
	}
	reason := args.Reason
	if reason == "" {
		reason = "Bulk allow via CLI"
	}
	allowed, failed, skipped := 0, 0, 0
	for _, ip := range args.IPs {
		if net.ParseIP(ip) == nil {
			skipped++
			continue
		}
		if err := c.d.fwEngine.AllowIP(ip, reason); err != nil {
			failed++
			continue
		}
		allowed++
	}
	msg := fmt.Sprintf("Allowed %d, skipped %d invalid", allowed, skipped)
	if failed > 0 {
		msg = fmt.Sprintf("Allowed %d, failed %d, skipped %d invalid", allowed, failed, skipped)
	}
	return control.FirewallAckResult{Message: msg}, nil
}

func (c *ControlListener) handleFirewallFlush(_ json.RawMessage) (any, error) {
	if c.d.fwEngine == nil {
		return nil, fmt.Errorf("firewall disabled in csm.yaml")
	}
	cfg := c.d.currentCfg()
	before, _ := firewall.LoadState(cfg.StatePath)
	count := len(before.Blocked)
	if err := c.d.fwEngine.FlushBlocked(); err != nil {
		return nil, fmt.Errorf("flushing blocked: %w", err)
	}
	return control.FirewallAckResult{
		Message: fmt.Sprintf("Flushed %d blocked IPs", count),
	}, nil
}

func (c *ControlListener) handleFirewallRestart(_ json.RawMessage) (any, error) {
	if c.d.fwEngine == nil {
		return nil, fmt.Errorf("firewall engine not running; restart the csm daemon")
	}
	if err := c.d.fwEngine.Apply(); err != nil {
		return nil, fmt.Errorf("applying ruleset: %w", err)
	}
	state, _ := firewall.LoadState(c.d.currentCfg().StatePath)
	return control.FirewallAckResult{
		Message: fmt.Sprintf("Firewall restarted. %d blocked, %d allowed IPs restored.", len(state.Blocked), len(state.Allowed)),
	}, nil
}

func (c *ControlListener) handleFirewallApplyConfirmed(argsRaw json.RawMessage) (any, error) {
	var args control.FirewallApplyConfirmedArgs
	if len(argsRaw) > 0 {
		if err := json.Unmarshal(argsRaw, &args); err != nil {
			return nil, fmt.Errorf("parsing args: %w", err)
		}
	}
	minutes := args.Minutes
	if minutes <= 0 || minutes > 60 {
		minutes = 3
	}

	if c.d.fwEngine == nil {
		return nil, fmt.Errorf("firewall engine not running; restart the csm daemon")
	}

	cfg := c.d.currentCfg()
	confirmFile := filepath.Join(cfg.StatePath, "firewall", "confirm_pending")
	rollbackFile := filepath.Join(cfg.StatePath, "firewall", "rollback.sh")

	// Capture current nftables ruleset for rollback. Best-effort: if
	// nft isn't installed or fails, proceed without rollback script.
	// #nosec G204 -- "nft list ruleset" is literal.
	nftDump, _ := exec.Command("nft", "list", "ruleset").Output()
	if len(nftDump) > 0 {
		rollbackScript := fmt.Sprintf("#!/bin/bash\n# Auto-rollback: restore previous nftables ruleset\nnft flush ruleset\nnft -f - <<'NFTEOF'\n%s\nNFTEOF\nrm -f %s %s\necho 'Firewall rolled back to previous state'\n",
			string(nftDump), confirmFile, rollbackFile)
		// #nosec G306 -- rollback script must be executable by root.
		_ = os.WriteFile(rollbackFile, []byte(rollbackScript), 0700)
	}

	if err := c.d.fwEngine.Apply(); err != nil {
		return nil, fmt.Errorf("applying ruleset: %w", err)
	}

	deadline := time.Now().Add(time.Duration(minutes) * time.Minute)
	if err := os.WriteFile(confirmFile, []byte(deadline.Format(time.RFC3339)), 0600); err != nil {
		return nil, fmt.Errorf("writing confirm marker: %w", err)
	}

	// Rollback goroutine lives in the daemon (long-lived, so it
	// survives CLI exit — an improvement over the old CLI version).
	obs.SafeGo("fw-apply-confirmed-rollback", func() {
		time.Sleep(time.Duration(minutes) * time.Minute)
		if _, err := os.Stat(confirmFile); err != nil {
			return // already confirmed (file removed)
		}
		if _, err := os.Stat(rollbackFile); err != nil {
			return
		}
		// #nosec G204 -- bash is hardcoded; rollbackFile path written above.
		cmd := exec.Command("bash", rollbackFile)
		_, _ = cmd.CombinedOutput()
	})

	state, _ := firewall.LoadState(cfg.StatePath)
	return control.FirewallAckResult{
		Message: fmt.Sprintf("Firewall applied with %d-minute rollback timer. %d blocked, %d allowed. Run `csm firewall confirm` to keep.", minutes, len(state.Blocked), len(state.Allowed)),
	}, nil
}

func (c *ControlListener) handleFirewallConfirm(_ json.RawMessage) (any, error) {
	cfg := c.d.currentCfg()
	confirmFile := filepath.Join(cfg.StatePath, "firewall", "confirm_pending")
	rollbackFile := filepath.Join(cfg.StatePath, "firewall", "rollback.sh")

	if _, err := os.Stat(confirmFile); os.IsNotExist(err) {
		return control.FirewallAckResult{
			Message: "No pending confirmation. Firewall is already confirmed.",
		}, nil
	}

	_ = os.Remove(confirmFile)
	_ = os.Remove(rollbackFile)
	return control.FirewallAckResult{
		Message: "Firewall confirmed. Rollback timer cancelled.",
	}, nil
}
