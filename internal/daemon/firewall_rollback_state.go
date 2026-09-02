package daemon

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// firewallStateSnapshotPath is where the apply-confirmed window keeps the
// pre-apply copy of state.json, beside the nft ruleset snapshot.
func firewallStateSnapshotPath(rollbackFile string) string {
	return rollbackFile + ".state.json"
}

func firewallStateFileFor(rollbackFile string) string {
	return filepath.Join(filepath.Dir(rollbackFile), "state.json")
}

// snapshotFirewallState copies state.json next to the rollback ruleset. The
// deadman used to restore the kernel snapshot alone, so an address
// unblocked inside the window came back blocked in the kernel while
// state.json, the UI and `csm firewall status` still said it was free.
// A missing state.json is recorded as an empty snapshot so the restore
// removes whatever the window wrote.
func snapshotFirewallState(rollbackFile string) error {
	data, err := os.ReadFile(firewallStateFileFor(rollbackFile)) // #nosec G304 -- CSM-owned state dir.
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("reading firewall state for rollback: %w", err)
	}
	// #nosec G306 G703 -- root-only state dir.
	if err := os.WriteFile(firewallStateSnapshotPath(rollbackFile), data, 0o600); err != nil {
		return fmt.Errorf("writing firewall state snapshot: %w", err)
	}
	return nil
}

// restoreFirewallStateSnapshot puts the snapshotted state.json back and
// removes the snapshot. No snapshot (an older window) is not an error.
func restoreFirewallStateSnapshot(rollbackFile string) error {
	snap := firewallStateSnapshotPath(rollbackFile)
	data, err := os.ReadFile(snap) // #nosec G304 -- CSM-owned state dir.
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("reading firewall state snapshot: %w", err)
	}
	stateFile := firewallStateFileFor(rollbackFile)
	if len(data) == 0 {
		if err := os.Remove(stateFile); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("removing firewall state written inside the window: %w", err)
		}
	} else if err := os.WriteFile(stateFile, data, 0o600); err != nil { // #nosec G306 G703 -- root-only state dir.
		return fmt.Errorf("restoring firewall state: %w", err)
	}
	return removeFileIfExists(snap)
}
