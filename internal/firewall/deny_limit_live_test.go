//go:build linux

package firewall

import (
	"net"
	"strings"
	"testing"
	"time"

	"github.com/google/nftables"
)

// TestBlockIPOutcome_DenyLimitCountsFromLiveSet asserts the temporary
// deny-limit gate counts entries from the live nft set rather than the
// possibly-stale state.json cache.
//
// Scenario: state.json says 3 temp entries (one stale), live nft has
// 2. DenyTempIPLimit is 3. With the old behaviour the third entry
// (stale state) would push temp>=cap and refuse the new block; with
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
	_ = e.saveBlockedEntry(BlockedEntry{IP: "198.51.100.1", Reason: "x", BlockedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour)})
	_ = e.saveBlockedEntry(BlockedEntry{IP: "198.51.100.2", Reason: "x", BlockedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour)})
	_ = e.saveBlockedEntry(BlockedEntry{IP: "198.51.100.3", Reason: "x", BlockedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour)})

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

func TestCountLiveBlockElementsUsesStateClassification(t *testing.T) {
	stateTempByIP := blockedStateTempByIP(FirewallState{Blocked: []BlockedEntry{
		{IP: "198.51.100.10", BlockedAt: time.Now()},
		{IP: "2001:db8::1", BlockedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour)},
	}})

	elements := []nftables.SetElement{
		// CSM state says permanent, even if nft reports timeout attrs.
		{Key: net.ParseIP("198.51.100.10").To4(), Timeout: time.Hour, Expires: 30 * time.Minute},
		// No CSM state: inherited/default expiration still means temporary.
		{Key: net.ParseIP("198.51.100.20").To4(), Expires: 30 * time.Minute},
		// CSM state says temporary, even if the live attrs are absent.
		{Key: net.ParseIP("2001:db8::1").To16()},
		// No state and no expiration attrs means permanent.
		{Key: net.ParseIP("2001:db8::2").To16()},
	}

	perm, temp := countLiveBlockElements(elements, stateTempByIP)
	if perm != 2 || temp != 2 {
		t.Fatalf("countLiveBlockElements = perm %d temp %d, want perm 2 temp 2", perm, temp)
	}
}
