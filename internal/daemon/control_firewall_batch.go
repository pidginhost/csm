package daemon

import (
	"bytes"
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
		// Operator-initiated batch: bypass auto_response.dry_run gate.
		if err := c.d.fwEngine.BlockIPForce(ip, reason, 0); err != nil {
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
	confirmFile, rollbackFile, legacyRollbackFile := firewallRollbackFiles(cfg.StatePath)

	if err := os.MkdirAll(filepath.Dir(rollbackFile), 0700); err != nil {
		return nil, fmt.Errorf("creating firewall rollback dir: %w", err)
	}
	if err := removeFirewallRollbackFiles(rollbackFile, legacyRollbackFile); err != nil {
		return nil, err
	}
	if err := writeFirewallRollbackFile(rollbackFile); err != nil {
		return nil, err
	}

	if err := c.d.fwEngine.Apply(); err != nil {
		_ = removeFileIfExists(rollbackFile)
		return nil, fmt.Errorf("applying ruleset: %w", err)
	}

	deadline := time.Now().Add(time.Duration(minutes) * time.Minute)
	if err := os.WriteFile(confirmFile, []byte(deadline.Format(time.RFC3339)), 0600); err != nil {
		if restoreErr := applyFirewallRollbackFile(rollbackFile); restoreErr != nil {
			_ = removeFileIfExists(confirmFile)
			return nil, fmt.Errorf("writing confirm marker: %w; rollback restore failed: %v", err, restoreErr)
		}
		_ = removeFirewallRollbackFiles(confirmFile, rollbackFile)
		return nil, fmt.Errorf("writing confirm marker: %w; previous ruleset restored", err)
	}

	// Rollback goroutine lives in the daemon (long-lived, so it
	// survives CLI exit -- an improvement over the old CLI version).
	obs.SafeGo("fw-apply-confirmed-rollback", func() {
		time.Sleep(time.Duration(minutes) * time.Minute)
		if err := restoreFirewallRollback(confirmFile, rollbackFile); err != nil {
			fmt.Fprintf(os.Stderr, "[%s] Firewall rollback failed: %v\n", ts(), err)
		}
	})

	state, _ := firewall.LoadState(cfg.StatePath)
	return control.FirewallAckResult{
		Message: fmt.Sprintf("Firewall applied with %d-minute rollback timer. %d blocked, %d allowed. Run `csm firewall confirm` to keep.", minutes, len(state.Blocked), len(state.Allowed)),
	}, nil
}

func (c *ControlListener) handleFirewallConfirm(_ json.RawMessage) (any, error) {
	cfg := c.d.currentCfg()
	confirmFile, rollbackFile, legacyRollbackFile := firewallRollbackFiles(cfg.StatePath)

	if _, err := os.Stat(confirmFile); err != nil {
		if !os.IsNotExist(err) {
			return nil, fmt.Errorf("checking confirm marker: %w", err)
		}
		if cleanupErr := removeFirewallRollbackFiles(rollbackFile, legacyRollbackFile); cleanupErr != nil {
			return nil, cleanupErr
		}
		return control.FirewallAckResult{
			Message: "No pending confirmation. Firewall is already confirmed.",
		}, nil
	}

	if err := removeFirewallRollbackFiles(confirmFile, rollbackFile, legacyRollbackFile); err != nil {
		return nil, err
	}
	return control.FirewallAckResult{
		Message: "Firewall confirmed. Rollback timer cancelled.",
	}, nil
}

func firewallRollbackFiles(statePath string) (confirmFile, rollbackFile, legacyRollbackFile string) {
	firewallDir := filepath.Join(statePath, "firewall")
	return filepath.Join(firewallDir, "confirm_pending"),
		filepath.Join(firewallDir, "rollback.nft"),
		filepath.Join(firewallDir, "rollback.sh")
}

func writeFirewallRollbackFile(rollbackFile string) error {
	// #nosec G204 -- "nft list ruleset" is literal.
	nftDump, err := exec.Command("nft", "list", "ruleset").Output()
	if err != nil {
		return fmt.Errorf("capturing rollback ruleset: %w", err)
	}

	// The dump is nft syntax, so store it as data consumed by nft -f.
	// An empty live ruleset still needs a rollback file; flush ruleset
	// restores that state.
	payload := make([]byte, 0, len("flush ruleset\n")+len(nftDump)+1)
	payload = append(payload, "flush ruleset\n"...)
	payload = append(payload, nftDump...)
	if len(nftDump) > 0 && nftDump[len(nftDump)-1] != '\n' {
		payload = append(payload, '\n')
	}

	// #nosec G306 -- root-only state dir; this is data, not an executable.
	if err := os.WriteFile(rollbackFile, payload, 0600); err != nil {
		_ = removeFileIfExists(rollbackFile)
		return fmt.Errorf("writing rollback ruleset: %w", err)
	}
	return nil
}

func restoreFirewallRollback(confirmFile, rollbackFile string) error {
	if _, err := os.Stat(confirmFile); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("checking confirm marker: %w", err)
	}
	if err := applyFirewallRollbackFile(rollbackFile); err != nil {
		return err
	}

	return removeFirewallRollbackFiles(confirmFile, rollbackFile, legacyRollbackFileFor(rollbackFile))
}

func applyFirewallRollbackFile(rollbackFile string) error {
	if _, err := os.Stat(rollbackFile); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("rollback ruleset missing")
		}
		return fmt.Errorf("checking rollback ruleset: %w", err)
	}

	// #nosec G204 -- nft is hardcoded; rollbackFile is a CSM-written path.
	out, err := exec.Command("nft", "-f", rollbackFile).CombinedOutput()
	if err != nil {
		out = bytes.TrimSpace(out)
		if len(out) > 0 {
			return fmt.Errorf("restoring rollback ruleset: %w: %s", err, out)
		}
		return fmt.Errorf("restoring rollback ruleset: %w", err)
	}
	return nil
}

func removeFirewallRollbackFiles(paths ...string) error {
	for _, path := range paths {
		if err := removeFileIfExists(path); err != nil {
			return err
		}
	}
	return nil
}

func legacyRollbackFileFor(rollbackFile string) string {
	return filepath.Join(filepath.Dir(rollbackFile), "rollback.sh")
}

func removeFileIfExists(path string) error {
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("removing %s: %w", filepath.Base(path), err)
	}
	return nil
}
