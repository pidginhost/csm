package daemon

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/pidginhost/csm/internal/control"
	"github.com/pidginhost/csm/internal/firewall"
	csmlog "github.com/pidginhost/csm/internal/log"
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

	if err := applyFirewallDeadman(confirmFile, rollbackFile, legacyRollbackFile,
		time.Duration(minutes)*time.Minute, c.d.fwEngine.Apply); err != nil {
		return nil, err
	}

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

// applyFirewallDeadman runs the tentative-apply protocol: snapshot the live
// ruleset, persist the confirm deadline, then apply the candidate. The
// marker is written BEFORE the kernel apply on purpose: a crash between the
// two leaves a valid deadline on disk for startup recovery to settle,
// whereas the reverse order would leave the candidate applied with no
// record that it was never confirmed (a permanent lockout).
func applyFirewallDeadman(confirmFile, rollbackFile, legacyRollbackFile string, window time.Duration, apply func() error) error {
	if err := os.MkdirAll(filepath.Dir(rollbackFile), 0700); err != nil {
		return fmt.Errorf("creating firewall rollback dir: %w", err)
	}
	if err := removeFirewallRollbackFiles(confirmFile, rollbackFile, legacyRollbackFile); err != nil {
		return err
	}
	if err := writeFirewallRollbackFile(rollbackFile); err != nil {
		return err
	}

	deadline := time.Now().Add(window)
	marker := []byte(deadline.Format(time.RFC3339))
	if err := os.WriteFile(confirmFile, marker, 0600); err != nil {
		_ = removeFirewallRollbackFiles(confirmFile, rollbackFile)
		return fmt.Errorf("writing confirm marker: %w", err)
	}

	if err := apply(); err != nil {
		// Apply may have partially mutated the kernel; re-applying the
		// snapshot is a no-op when it did not, and the undo when it did.
		if restoreErr := applyFirewallRollbackFile(rollbackFile); restoreErr != nil {
			// Keep marker + snapshot: the deadline stands, so the armed
			// deadman retries the restore at expiry (and startup recovery
			// does the same after a crash).
			armFirewallDeadman(confirmFile, rollbackFile, marker, time.Until(deadline))
			return fmt.Errorf("applying ruleset: %w; rollback restore failed: %v", err, restoreErr)
		}
		if cleanupErr := removeFirewallRollbackFiles(confirmFile, rollbackFile); cleanupErr != nil {
			return fmt.Errorf("applying ruleset: %w; %v", err, cleanupErr)
		}
		return fmt.Errorf("applying ruleset: %w; previous ruleset restored", err)
	}

	armFirewallDeadman(confirmFile, rollbackFile, marker, window)
	return nil
}

// armFirewallDeadman restores the pre-apply ruleset once wait elapses unless
// the operator confirms first. The goroutine lives in the daemon (long-lived,
// so it survives CLI exit); a daemon restart kills it, which is why
// recoverFirewallApplyConfirmed re-arms from the persisted deadline.
func armFirewallDeadman(confirmFile, rollbackFile string, marker []byte, wait time.Duration) {
	obs.SafeGo("fw-apply-confirmed-rollback", func() {
		time.Sleep(wait)
		if err := restoreFirewallRollback(confirmFile, rollbackFile, marker); err != nil {
			fmt.Fprintf(os.Stderr, "[%s] Firewall rollback failed: %v\n", ts(), err)
		}
	})
}

// recoverFirewallApplyConfirmed settles an apply-confirmed window that a
// daemon restart interrupted. Without it the restart kills the deadman
// goroutine and startFirewall re-applies the unconfirmed candidate, making
// permanent exactly the lockout the command exists to prevent. Must run
// after startFirewall so an expired-window restore lands on top of the
// candidate ruleset the startup Apply just re-applied, and before the
// control listener starts so confirm/cancel cannot race the recovery.
func (d *Daemon) recoverFirewallApplyConfirmed() {
	confirmFile, rollbackFile, legacyRollbackFile := firewallRollbackFiles(d.cfg.StatePath)

	marker, err := os.ReadFile(confirmFile) // #nosec G304 -- CSM-owned marker under the state dir.
	if err != nil {
		if !os.IsNotExist(err) {
			csmlog.Warn("firewall confirm marker unreadable; leaving apply-confirmed state untouched", "err", err)
			return
		}
		// No marker means no candidate reached the kernel with a pending
		// window (the marker is written before the apply), so a leftover
		// snapshot is debris from an aborted handler run.
		if cleanupErr := removeFirewallRollbackFiles(rollbackFile, legacyRollbackFile); cleanupErr != nil {
			csmlog.Warn("firewall rollback snapshot cleanup failed", "err", cleanupErr)
		}
		return
	}

	deadline, parseErr := time.Parse(time.RFC3339, strings.TrimSpace(string(marker)))
	if parseErr != nil {
		// Fail safe: an unconfirmed ruleset must never outlive its
		// deadline, and a corrupt marker gives no deadline to honour.
		csmlog.Warn("firewall confirm marker corrupt; restoring previous ruleset", "err", parseErr)
		if restoreErr := restoreFirewallRollback(confirmFile, rollbackFile, marker); restoreErr != nil {
			csmlog.Warn("firewall rollback failed", "err", restoreErr)
		}
		return
	}

	if remaining := time.Until(deadline); remaining > 0 {
		// startFirewall already re-applied the candidate, matching the
		// kernel state from before the restart, so the operator keeps the
		// verification window they asked for; the re-armed deadman still
		// bounds it with the original deadline.
		armFirewallDeadman(confirmFile, rollbackFile, marker, remaining)
		csmlog.Info("firewall apply-confirmed window resumed after restart",
			"deadline", deadline.Format(time.RFC3339))
		return
	}

	if restoreErr := restoreFirewallRollback(confirmFile, rollbackFile, marker); restoreErr != nil {
		csmlog.Warn("firewall rollback failed", "err", restoreErr)
		return
	}
	csmlog.Warn("firewall apply-confirmed window expired during restart; previous ruleset restored",
		"deadline", deadline.Format(time.RFC3339))
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

func restoreFirewallRollback(confirmFile, rollbackFile string, expectedMarker []byte) error {
	raw, err := os.ReadFile(confirmFile) // #nosec G304 -- CSM-owned marker under the state dir.
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("checking confirm marker: %w", err)
	}
	// A different marker means a newer apply-confirmed window owns the
	// files now; this caller's window was superseded and firing would
	// roll the newer window back before its own deadline.
	if !bytes.Equal(raw, expectedMarker) {
		return nil
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
