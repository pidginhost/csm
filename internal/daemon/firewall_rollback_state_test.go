package daemon

import (
	"os"
	"path/filepath"
	"testing"
)

// The apply-confirmed deadman restored the kernel ruleset from an nft
// snapshot but never touched state.json, so an address unblocked inside
// the window came back blocked in the kernel while the UI and `csm
// firewall status` said it was free. The snapshot now carries state.json
// and the restore puts it back.
func TestFirewallRollbackSnapshotCarriesStateJSON(t *testing.T) {
	dir := t.TempDir()
	fwDir := filepath.Join(dir, "firewall")
	if err := os.MkdirAll(fwDir, 0o700); err != nil {
		t.Fatal(err)
	}
	stateFile := filepath.Join(fwDir, "state.json")
	before := `{"blocked":[{"ip":"203.0.113.9","reason":"before"}]}`
	if err := os.WriteFile(stateFile, []byte(before), 0o600); err != nil {
		t.Fatal(err)
	}
	rollbackFile := filepath.Join(fwDir, "rollback.nft")

	if err := snapshotFirewallState(rollbackFile); err != nil {
		t.Fatal(err)
	}
	// Mutation inside the window.
	if err := os.WriteFile(stateFile, []byte(`{"blocked":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := restoreFirewallStateSnapshot(rollbackFile); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(stateFile)
	if err != nil || string(got) != before {
		t.Fatalf("state.json after rollback = %q, %v; want the pre-window content", got, err)
	}
	if _, err := os.Stat(firewallStateSnapshotPath(rollbackFile)); !os.IsNotExist(err) {
		t.Fatalf("state snapshot left behind after restore: %v", err)
	}
}
