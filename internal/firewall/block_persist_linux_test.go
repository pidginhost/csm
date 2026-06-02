//go:build linux

package firewall

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/nftables"
	"github.com/pidginhost/csm/internal/atomicio"
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

func TestSaveBlockedEntryAcceptsCommittedWriteWarning(t *testing.T) {
	prev := writeFirewallStateJSON
	t.Cleanup(func() { writeFirewallStateJSON = prev })
	writeFirewallStateJSON = func(path string, perm os.FileMode, v any) error {
		if err := atomicio.AtomicWriteJSON(path, perm, v); err != nil {
			return err
		}
		return errors.New("sync state dir")
	}

	e := &Engine{statePath: t.TempDir(), cfg: &FirewallConfig{}}
	if err := e.saveBlockedEntry(BlockedEntry{IP: "203.0.113.3", Reason: "test"}); err != nil {
		t.Fatalf("saveBlockedEntry returned error after committed write: %v", err)
	}
	if !e.IsBlocked("203.0.113.3") {
		t.Fatal("committed write warning should refresh blocked cache")
	}
}

func TestBlockIPReportsStateRestoreFailure(t *testing.T) {
	prev := writeFirewallStateJSON
	t.Cleanup(func() { writeFirewallStateJSON = prev })

	writes := 0
	writeFirewallStateJSON = func(path string, perm os.FileMode, v any) error {
		writes++
		if writes == 1 {
			return atomicio.AtomicWriteJSON(path, perm, v)
		}
		return errors.New("restore denied")
	}

	e := &Engine{
		conn:       &nftables.Conn{},
		statePath:  t.TempDir(),
		cfg:        &FirewallConfig{Enabled: true},
		setBlocked: anonymousIPv4Set("blocked_ips"),
	}

	err := e.BlockIPForce("203.0.113.4", "manual block", time.Hour)
	if err == nil {
		t.Fatal("expected nftables queue error")
	}
	if !strings.Contains(err.Error(), "adding to blocked set") {
		t.Fatalf("error %q does not report the nftables operation", err)
	}
	if !strings.Contains(err.Error(), "state restore failed: restore denied") {
		t.Fatalf("error %q does not report the rollback failure", err)
	}
	if writes != 2 {
		t.Fatalf("state writes = %d, want persist plus restore", writes)
	}
}

func TestPromoteToPermanentBlockHonorsPermanentDenyLimit(t *testing.T) {
	dir := t.TempDir()
	e := &Engine{
		statePath:  dir,
		cfg:        &FirewallConfig{Enabled: true, DenyIPLimit: 1},
		setBlocked: anonymousIPv4Set("blocked_ips"),
	}
	tempExpires := time.Now().Add(time.Hour)
	state := FirewallState{Blocked: []BlockedEntry{
		{IP: "192.0.2.10", Reason: "existing permanent", BlockedAt: time.Now().Add(-2 * time.Hour)},
		{IP: "192.0.2.11", Reason: "temporary", BlockedAt: time.Now().Add(-time.Minute), ExpiresAt: tempExpires},
	}}
	if err := e.saveState(&state); err != nil {
		t.Fatalf("save state: %v", err)
	}

	err := e.PromoteToPermanentBlock("192.0.2.11", "PERMBLOCK: test")
	if err == nil {
		t.Fatal("expected promotion to respect permanent deny limit")
	}
	if !strings.Contains(err.Error(), "permanent deny limit reached") {
		t.Fatalf("PromoteToPermanentBlock error = %v, want permanent deny limit", err)
	}

	got := e.loadStateFile()
	for _, entry := range got.Blocked {
		if entry.IP != "192.0.2.11" {
			continue
		}
		if entry.ExpiresAt.IsZero() {
			t.Fatal("temporary entry was promoted in state despite deny-limit refusal")
		}
		if entry.Reason != "temporary" {
			t.Fatalf("temporary entry reason changed to %q", entry.Reason)
		}
		return
	}
	t.Fatal("temporary entry missing after denied promotion")
}
