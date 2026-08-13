package checks

import (
	"errors"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/firewall"
)

var errSnapshotUnavailable = errors.New("nftables connection unavailable")

// snapshotBlocker implements IPBlocker plus both the per-IP liveBlocker
// shape and the bulk liveBlockedLister shape, counting calls to each. The
// reconcile pass must dump the blocked set once per cycle instead of once
// per tracked IP, so these two counters are the assertion that matters.
type snapshotBlocker struct {
	snap       firewall.LiveBlockedSnapshot
	snapErr    error
	snapCalls  int
	liveCalls  int
	cachedSays bool
	liveSays   bool
}

func (b *snapshotBlocker) BlockIP(string, string, time.Duration) error { return nil }
func (b *snapshotBlocker) UnblockIP(string) error                      { return nil }
func (b *snapshotBlocker) IsBlocked(string) bool                       { return b.cachedSays }

func (b *snapshotBlocker) IsBlockedLive(string) (bool, error) {
	b.liveCalls++
	return b.liveSays, nil
}

func (b *snapshotBlocker) LiveBlockedSet() (firewall.LiveBlockedSnapshot, error) {
	b.snapCalls++
	return b.snap, b.snapErr
}

func reconcileWithBlocker(t *testing.T, blocker IPBlocker, seeded ...blockedIP) *blockState {
	t.Helper()
	cfg := newAutoBlockTestConfig(t)
	cfg.AutoResponse.Enabled = true
	cfg.AutoResponse.BlockIPs = true

	saveBlockState(cfg.StatePath, &blockState{IPs: seeded})
	swapBlocker(t, blocker)

	_ = AutoBlockIPs(cfg, nil)
	return loadBlockState(cfg.StatePath)
}

func trackedIP(ip string) blockedIP {
	return blockedIP{IP: ip, Reason: "test", BlockedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour)}
}

// C1: the reconcile pass used to call IsBlockedLive per tracked IP, and each
// of those calls dumped the entire nftables set over netlink. One bulk dump
// must now answer for every tracked IP.
func TestAutoBlockIPs_ReconcileDumpsBlockedSetOnce(t *testing.T) {
	blocker := &snapshotBlocker{
		snap: firewall.LiveBlockedSnapshot{
			V4:    map[string]struct{}{"192.0.2.10": {}, "192.0.2.11": {}},
			V6:    map[string]struct{}{"2001:db8::1": {}},
			HasV4: true,
			HasV6: true,
		},
	}

	state := reconcileWithBlocker(t, blocker,
		trackedIP("192.0.2.10"), trackedIP("192.0.2.11"), trackedIP("2001:db8::1"))

	if len(state.IPs) != 3 {
		t.Errorf("live-blocked entries must survive reconcile, kept %d of 3: %+v", len(state.IPs), state.IPs)
	}
	if blocker.snapCalls != 1 {
		t.Errorf("blocked set dumped %d times, want exactly 1 for the whole cycle", blocker.snapCalls)
	}
	if blocker.liveCalls != 0 {
		t.Errorf("per-IP live lookups = %d, want 0 once a bulk snapshot is available", blocker.liveCalls)
	}
}

// An entry the kernel no longer holds must still be pruned; the bulk path
// must not turn the reconcile into a no-op.
func TestAutoBlockIPs_ReconcilePrunesAbsentFromSnapshot(t *testing.T) {
	blocker := &snapshotBlocker{
		cachedSays: true, // cache lags, as it does when nft expires an entry
		snap: firewall.LiveBlockedSnapshot{
			V4:    map[string]struct{}{"192.0.2.10": {}},
			HasV4: true,
			HasV6: true,
		},
	}

	state := reconcileWithBlocker(t, blocker, trackedIP("192.0.2.10"), trackedIP("192.0.2.99"))

	if len(state.IPs) != 1 || state.IPs[0].IP != "192.0.2.10" {
		t.Errorf("expected only the live entry retained, got %+v", state.IPs)
	}
}

// A snapshot that does not cover an address family must not read as "absent".
// On a host with firewall.ipv6 disabled the v6 set is nil, and treating that
// as "not blocked" would prune every tracked v6 block on the first cycle.
func TestAutoBlockIPs_ReconcileKeepsUncoveredFamily(t *testing.T) {
	blocker := &snapshotBlocker{
		cachedSays: true,
		snap: firewall.LiveBlockedSnapshot{
			V4:    map[string]struct{}{},
			HasV4: true,
			HasV6: false,
		},
	}

	state := reconcileWithBlocker(t, blocker, trackedIP("2001:db8::1"))

	if len(state.IPs) != 1 {
		t.Errorf("v6 entry pruned despite the snapshot not covering v6: %+v", state.IPs)
	}
	if blocker.liveCalls != 0 {
		t.Errorf("uncovered family triggered %d live retries, want the cached answer", blocker.liveCalls)
	}
}

// A failed dump must leave the tracker alone rather than erase it, matching
// what the per-IP path does when netlink errors.
func TestAutoBlockIPs_ReconcileKeepsStateWhenSnapshotFails(t *testing.T) {
	blocker := &snapshotBlocker{
		cachedSays: true,
		snapErr:    errSnapshotUnavailable,
	}

	state := reconcileWithBlocker(t, blocker, trackedIP("192.0.2.10"))

	if len(state.IPs) != 1 {
		t.Errorf("tracker erased on a transient dump failure: %+v", state.IPs)
	}
	if blocker.liveCalls != 0 {
		t.Errorf("failed bulk dump triggered %d live retries, want the cached answer", blocker.liveCalls)
	}
}

func TestAutoBlockIPs_ReconcileTreatsMalformedIPAsAbsentAfterSnapshotFailure(t *testing.T) {
	blocker := &snapshotBlocker{
		cachedSays: true,
		snapErr:    errSnapshotUnavailable,
	}

	state := reconcileWithBlocker(t, blocker, trackedIP("not-an-ip"))

	if len(state.IPs) != 0 {
		t.Errorf("malformed tracker entry survived reconcile: %+v", state.IPs)
	}
	if blocker.liveCalls != 0 {
		t.Errorf("malformed IP triggered %d live retries, want definitive absence", blocker.liveCalls)
	}
}

// A dump that failed for one family still carries the other family's live
// membership. The covered family must be reconciled from it rather than
// dropped to cached status because its sibling failed.
func TestAutoBlockIPs_ReconcileUsesCoveredFamilyOfPartialSnapshot(t *testing.T) {
	blocker := &snapshotBlocker{
		cachedSays: true, // cache lags: it still claims both entries are blocked
		snapErr:    errSnapshotUnavailable,
		snap: firewall.LiveBlockedSnapshot{
			V4:    map[string]struct{}{},
			HasV4: true,
			HasV6: false,
		},
	}

	state := reconcileWithBlocker(t, blocker, trackedIP("192.0.2.10"), trackedIP("2001:db8::1"))

	if len(state.IPs) != 1 || state.IPs[0].IP != "2001:db8::1" {
		t.Errorf("want the v4 entry pruned from the covered family and the v6 entry kept from cache, got %+v", state.IPs)
	}
	if blocker.liveCalls != 0 {
		t.Errorf("partial snapshot triggered %d per-IP live retries, want 0", blocker.liveCalls)
	}
}

func TestAutoBlockIPs_ReconcileMatchesIPv4MappedEntryInV4Snapshot(t *testing.T) {
	blocker := &snapshotBlocker{
		snap: firewall.LiveBlockedSnapshot{
			V4:    map[string]struct{}{"192.0.2.10": {}},
			HasV4: true,
		},
	}

	state := reconcileWithBlocker(t, blocker, trackedIP("::ffff:192.0.2.10"))

	if len(state.IPs) != 1 {
		t.Errorf("IPv4-mapped tracker entry did not match the v4 snapshot: %+v", state.IPs)
	}
	if blocker.liveCalls != 0 {
		t.Errorf("IPv4-mapped lookup triggered %d live retries, want snapshot match", blocker.liveCalls)
	}
}
