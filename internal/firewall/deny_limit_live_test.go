//go:build linux

package firewall

import (
	"strings"
	"testing"
	"time"

	"github.com/google/nftables"
)

// TestBlockIPOutcome_DenyLimitCountsFromLiveSet asserts the temporary
// deny-limit gate counts entries from the live nft set rather than the
// possibly-stale state.json cache. F10 already made IsBlocked live; F8
// extends the same correctness to the cap.
//
// Scenario: state.json says 3 temp entries (one stale), live nft has
// 2. DenyTempIPLimit is 3. With the old behaviour the third entry
// (stale state) would push perm>=cap and refuse the new block; with
// the live-counted fix the cap sees 2 and admits the block.
func TestBlockIPOutcome_DenyLimitCountsFromLiveSet(t *testing.T) {
	dir := t.TempDir()
	e := &Engine{
		cfg:           &FirewallConfig{Enabled: true, DenyTempIPLimit: 3},
		statePath:     dir,
		dryRunEnabled: func() bool { return true },
		liveBlockLookup: func(_ *nftables.Set, _ []byte) (bool, error) {
			// new IP is not live yet; allow validateBlockIP to proceed.
			return false, nil
		},
		liveBlockCounts: func() (int, int, error) {
			return 0, 2, nil
		},
	}
	// Seed state.json with 3 stale temp blocks to exceed the cap if
	// the count was sourced from state.
	e.saveBlockedEntry(BlockedEntry{IP: "198.51.100.1", Reason: "x", BlockedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour)})
	e.saveBlockedEntry(BlockedEntry{IP: "198.51.100.2", Reason: "x", BlockedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour)})
	e.saveBlockedEntry(BlockedEntry{IP: "198.51.100.3", Reason: "x", BlockedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour)})

	outcome, err := e.BlockIPOutcome("198.51.100.4", "new", time.Hour)
	if err != nil {
		t.Fatalf("BlockIPOutcome: %v", err)
	}
	if outcome != BlockOutcomeDryRun {
		t.Errorf("outcome = %q, want %q (cap should admit when live count is below cap)", outcome, BlockOutcomeDryRun)
	}
}

// TestBlockIPOutcome_DenyLimitTripsOnLiveCount also confirms the gate
// still fires when the live count is at the cap, so we did not
// accidentally turn the cap off.
func TestBlockIPOutcome_DenyLimitTripsOnLiveCount(t *testing.T) {
	dir := t.TempDir()
	e := &Engine{
		cfg:           &FirewallConfig{Enabled: true, DenyTempIPLimit: 2},
		statePath:     dir,
		dryRunEnabled: func() bool { return true },
		liveBlockLookup: func(_ *nftables.Set, _ []byte) (bool, error) {
			return false, nil
		},
		liveBlockCounts: func() (int, int, error) {
			return 0, 2, nil
		},
	}

	_, err := e.BlockIPOutcome("198.51.100.5", "new", time.Hour)
	if err == nil || !strings.Contains(err.Error(), "temporary deny limit reached") {
		t.Fatalf("expected temporary deny limit refusal, got %v", err)
	}
}
