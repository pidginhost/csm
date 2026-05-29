//go:build linux

package firewall

import (
	"path/filepath"
	"testing"
)

// TestSaveBlockedEntryPropagatesPersistError pins that a failed state
// persist surfaces an error to the caller. blockIPLocked relies on this
// to roll the live nft element back so a block that did not survive to
// disk cannot silently vanish on the next Apply().
func TestSaveBlockedEntryPropagatesPersistError(t *testing.T) {
	// statePath points at a directory that does not exist, so the atomic
	// write's temp-file create fails and the error must propagate.
	e := &Engine{statePath: filepath.Join(t.TempDir(), "missing-subdir"), cfg: &FirewallConfig{}}

	if err := e.saveBlockedEntry(BlockedEntry{IP: "203.0.113.1", Reason: "test"}); err == nil {
		t.Fatal("expected saveBlockedEntry to return an error when the state dir is missing")
	}
}

// TestSaveBlockedEntrySucceedsWhenWritable confirms the happy path still
// persists and reports no error.
func TestSaveBlockedEntrySucceedsWhenWritable(t *testing.T) {
	e := &Engine{statePath: t.TempDir(), cfg: &FirewallConfig{}}

	if err := e.saveBlockedEntry(BlockedEntry{IP: "203.0.113.2", Reason: "test"}); err != nil {
		t.Fatalf("saveBlockedEntry on writable dir: %v", err)
	}
	if c := e.RuleCounts(); c.Blocked != 1 {
		t.Errorf("Blocked count after persist = %d, want 1", c.Blocked)
	}
}
