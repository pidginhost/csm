//go:build linux

package firewall

import (
	"errors"
	"net"
	"testing"
	"time"

	"github.com/google/nftables"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

// delSetElemCount counts the DELSETELEM messages in the captured batch that
// target setName.
func delSetElemCount(t *testing.T, msgs []netlink.Message, setName string) int {
	t.Helper()
	const nlaTypeMask = 0x3fff
	delElem := netlink.HeaderType(unix.NFNL_SUBSYS_NFTABLES<<8 | unix.NFT_MSG_DELSETELEM)
	n := 0
	for _, m := range msgs {
		if m.Header.Type != delElem || len(m.Data) < 4 {
			continue
		}
		attrs, err := netlink.UnmarshalAttributes(m.Data[4:])
		if err != nil {
			t.Fatalf("unmarshal DELSETELEM attributes: %v", err)
		}
		for _, a := range attrs {
			if a.Type&nlaTypeMask == unix.NFTA_SET_ELEM_LIST_SET && string(a.Data) == setName+"\x00" {
				n++
			}
		}
	}
	return n
}

// nf_tables treats NEWSETELEM without NLM_F_EXCL on an existing key as an
// acknowledged no-op: the element keeps its old timeout. An operator deny on
// an auto-blocked address therefore left the kernel expiring the block after
// the original hour while state.json, the UI and `csm firewall status` all
// said permanent. The forced path must replace the element, as promotion does.
func TestBlockIPForceReplacesExistingElementTimeout(t *testing.T) {
	conn, captured := nftConnCapturingRules(t)
	e := newBlockedSetWireTestEngine(t, conn)
	writeRawFirewallState(t, e, FirewallState{
		Blocked: []BlockedEntry{{
			IP:        "192.0.2.13",
			Reason:    "auto-block",
			BlockedAt: time.Now(),
			ExpiresAt: time.Now().Add(time.Hour),
		}},
	})

	if err := e.BlockIPForce("192.0.2.13", "operator deny", 0); err != nil {
		t.Fatalf("BlockIPForce: %v", err)
	}

	if got := delSetElemCount(t, *captured, "blocked_ips"); got != 1 {
		t.Fatalf("blocked_ips element deletes = %d, want 1 (the timed element must go before the permanent re-add)", got)
	}
	timeouts := newSetElemTimeouts(t, *captured, "blocked_ips")
	if len(timeouts) != 1 || timeouts[0] != nil {
		t.Fatalf("blocked_ips element adds = %v, want exactly one add with no timeout", timeouts)
	}
	state := readRawFirewallState(t, e)
	if len(state.Blocked) != 1 || !state.Blocked[0].ExpiresAt.IsZero() {
		t.Fatalf("state after deny = %+v, want one permanent entry", state.Blocked)
	}
}

// The inverse drift: a temporary ban laid over a permanent block must expire
// in the kernel when state.json says it does, or the address stays dropped
// forever while every CSM surface reports it unblocked.
func TestBlockIPForceTempBanOverPermanentReplacesElement(t *testing.T) {
	conn, captured := nftConnCapturingRules(t)
	e := newBlockedSetWireTestEngine(t, conn)
	writeRawFirewallState(t, e, FirewallState{
		Blocked: []BlockedEntry{{
			IP:        "192.0.2.14",
			Reason:    "operator deny",
			BlockedAt: time.Now(),
		}},
	})

	if err := e.BlockIPForce("192.0.2.14", "tempban", 24*time.Hour); err != nil {
		t.Fatalf("BlockIPForce: %v", err)
	}

	if got := delSetElemCount(t, *captured, "blocked_ips"); got != 1 {
		t.Fatalf("blocked_ips element deletes = %d, want 1", got)
	}
	timeouts := newSetElemTimeouts(t, *captured, "blocked_ips")
	if len(timeouts) != 1 || timeouts[0] == nil || *timeouts[0] != 24*time.Hour {
		t.Fatalf("blocked_ips element adds = %v, want one add carrying the 24h timeout", timeouts)
	}
}

// A first-time block has nothing to replace; it must stay a plain add so a
// missing element never turns the batch into an ENOENT failure.
func TestBlockIPForceNewAddressDoesNotDelete(t *testing.T) {
	conn, captured := nftConnCapturingRules(t)
	e := newBlockedSetWireTestEngine(t, conn)
	e.liveBlockLookup = func(*nftables.Set, []byte) (bool, error) { return false, nil }

	if err := e.BlockIPForce("192.0.2.15", "operator deny", 0); err != nil {
		t.Fatalf("BlockIPForce: %v", err)
	}
	if got := delSetElemCount(t, *captured, "blocked_ips"); got != 0 {
		t.Fatalf("blocked_ips element deletes = %d, want 0 for a new address", got)
	}
}

func TestBlockIPForceReplacesLiveElementMissingFromState(t *testing.T) {
	conn, captured := nftConnCapturingRules(t)
	e := newBlockedSetWireTestEngine(t, conn)
	e.liveBlockLookup = func(*nftables.Set, []byte) (bool, error) { return true, nil }

	if err := e.BlockIPForce("192.0.2.25", "operator deny", 0); err != nil {
		t.Fatalf("BlockIPForce with drifted state: %v", err)
	}
	if got := delSetElemCount(t, *captured, "blocked_ips"); got != 1 {
		t.Fatalf("blocked_ips element deletes = %d, want 1 for the live untracked element", got)
	}
	state := readRawFirewallState(t, e)
	if len(state.Blocked) != 1 || state.Blocked[0].IP != "192.0.2.25" || !state.Blocked[0].ExpiresAt.IsZero() {
		t.Fatalf("state after drift repair = %+v, want one permanent block", state.Blocked)
	}
}

func TestBlockIPForceReplacesUntrackedLiveElementAtLimit(t *testing.T) {
	for _, tc := range []struct {
		name      string
		ip        string
		timeout   time.Duration
		perm, tmp int
		configure func(*FirewallConfig)
	}{
		{
			name:      "permanent",
			ip:        "192.0.2.26",
			perm:      1,
			configure: func(cfg *FirewallConfig) { cfg.DenyIPLimit = 1 },
		},
		{
			name:      "temporary",
			ip:        "192.0.2.27",
			timeout:   2 * time.Hour,
			tmp:       1,
			configure: func(cfg *FirewallConfig) { cfg.DenyTempIPLimit = 1 },
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conn, _ := nftConnCapturingRules(t)
			e := newBlockedSetWireTestEngine(t, conn)
			tc.configure(e.cfg)
			e.liveBlockCounts = func() (int, int, error) { return tc.perm, tc.tmp, nil }
			e.liveBlockLookup = func(*nftables.Set, []byte) (bool, error) { return true, nil }
			e.liveBlockedDump = func(*nftables.Set) ([]nftables.SetElement, error) {
				return []nftables.SetElement{{Key: net.ParseIP(tc.ip).To4(), Timeout: tc.timeout}}, nil
			}

			if err := e.BlockIPForce(tc.ip, "replacement", tc.timeout); err != nil {
				t.Fatalf("BlockIPForce for untracked live element at limit: %v", err)
			}
		})
	}
}

// Replacing an entry does not consume another limit slot. A full temporary or
// permanent set must still allow an operator to refresh the timeout of the IP
// already occupying that slot.
func TestBlockIPForceReblockAtConfiguredLimit(t *testing.T) {
	for _, tc := range []struct {
		name      string
		timeout   time.Duration
		entry     BlockedEntry
		perm, tmp int
		configure func(*FirewallConfig)
	}{
		{
			name:    "temporary",
			timeout: 2 * time.Hour,
			entry: BlockedEntry{IP: "192.0.2.16", Reason: "old temp", BlockedAt: time.Now(),
				ExpiresAt: time.Now().Add(time.Hour)},
			tmp:       1,
			configure: func(cfg *FirewallConfig) { cfg.DenyTempIPLimit = 1 },
		},
		{
			name:      "permanent",
			entry:     BlockedEntry{IP: "192.0.2.17", Reason: "old deny", BlockedAt: time.Now()},
			perm:      1,
			configure: func(cfg *FirewallConfig) { cfg.DenyIPLimit = 1 },
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conn, _ := nftConnCapturingRules(t)
			e := newBlockedSetWireTestEngine(t, conn)
			tc.configure(e.cfg)
			e.liveBlockCounts = func() (int, int, error) { return tc.perm, tc.tmp, nil }
			e.liveBlockLookup = func(*nftables.Set, []byte) (bool, error) { return true, nil }
			writeRawFirewallState(t, e, FirewallState{Blocked: []BlockedEntry{tc.entry}})

			if err := e.BlockIPForce(tc.entry.IP, "replacement", tc.timeout); err != nil {
				t.Fatalf("BlockIPForce at the configured limit: %v", err)
			}
		})
	}
}

func TestBlockIPForceRetriesExpiredReplacementElement(t *testing.T) {
	conn, sends := nftConnReturningErrsThenOK(t, unix.ENOENT)
	e := newBlockedSetWireTestEngine(t, conn)
	// state.json still carries the block as live (the engine prunes expired
	// entries on load), but the kernel has already dropped the element: a
	// clock difference or an out-of-band nft flush. The delete in the
	// replace batch therefore fails with ENOENT.
	writeRawFirewallState(t, e, FirewallState{Blocked: []BlockedEntry{{
		IP: "192.0.2.22", Reason: "auto-block", BlockedAt: time.Now(),
		ExpiresAt: time.Now().Add(time.Hour),
	}}})

	if err := e.BlockIPForce("192.0.2.22", "operator deny", 0); err != nil {
		t.Fatalf("BlockIPForce after replacement expired: %v", err)
	}
	if sends() != 2 {
		t.Fatalf("netlink sends = %d, want failed replace plus add-only retry", sends())
	}
	state := readRawFirewallState(t, e)
	if len(state.Blocked) != 1 || !state.Blocked[0].ExpiresAt.IsZero() {
		t.Fatalf("state after expired replacement retry = %+v, want permanent block", state.Blocked)
	}
}

// Either delete in the atomic replace+evict batch may race an expiring kernel
// element. If the eviction victim disappeared, retrying the same stale delete
// forever prevents the forced re-block even though both missing elements are
// benign. The retry sequence must handle the replacement and eviction paths
// symmetrically while keeping an existing target blocked until its replacement
// is queued in the same batch.
func TestBlockIPForceRetriesMissingEvictionElement(t *testing.T) {
	conn, sends := nftConnReturningErrsThenOK(t, unix.ENOENT, unix.ENOENT)
	e := newBlockedSetWireTestEngine(t, conn)
	e.cfg.DenyTempIPLimit = 1
	e.liveBlockCounts = func() (int, int, error) { return 1, 1, nil }
	e.liveBlockLookup = func(_ *nftables.Set, key []byte) (bool, error) {
		if len(key) == 0 {
			return false, errors.New("empty key")
		}
		return true, nil
	}
	now := time.Now()
	writeRawFirewallState(t, e, FirewallState{Blocked: []BlockedEntry{
		{IP: "192.0.2.18", Reason: "permanent", BlockedAt: now},
		{IP: "192.0.2.19", Reason: "expiring victim", BlockedAt: now, ExpiresAt: now.Add(time.Minute)},
	}})

	if err := e.BlockIPForce("192.0.2.18", "replace with temp", 2*time.Hour); err != nil {
		t.Fatalf("BlockIPForce after stale eviction delete: %v", err)
	}
	if sends() != 3 {
		t.Fatalf("netlink sends = %d, want initial batch plus two bounded retries", sends())
	}
	state := readRawFirewallState(t, e)
	if len(state.Blocked) != 1 || state.Blocked[0].IP != "192.0.2.18" || state.Blocked[0].ExpiresAt.IsZero() {
		t.Fatalf("state after retry = %+v, want only the replacement temporary block", state.Blocked)
	}
}

func TestBlockIPForceNewBlockRetriesMissingEvictionElement(t *testing.T) {
	conn, sends := nftConnReturningErrsThenOK(t, unix.ENOENT)
	e := newBlockedSetWireTestEngine(t, conn)
	e.cfg.DenyTempIPLimit = 1
	e.liveBlockCounts = func() (int, int, error) { return 0, 1, nil }
	now := time.Now()
	writeRawFirewallState(t, e, FirewallState{Blocked: []BlockedEntry{{
		IP: "192.0.2.20", Reason: "expired victim", BlockedAt: now, ExpiresAt: now.Add(time.Minute),
	}}})

	if err := e.BlockIPForce("192.0.2.21", "new temp", 2*time.Hour); err != nil {
		t.Fatalf("BlockIPForce after stale eviction delete: %v", err)
	}
	if sends() != 2 {
		t.Fatalf("netlink sends = %d, want initial batch plus add-only retry", sends())
	}
	state := readRawFirewallState(t, e)
	if len(state.Blocked) != 1 || state.Blocked[0].IP != "192.0.2.21" {
		t.Fatalf("state after retry = %+v, want only the new temporary block", state.Blocked)
	}
}

func TestBlockIPForceRetriesWhenReplacementAndEvictionBothExpire(t *testing.T) {
	conn, sends := nftConnReturningErrsThenOK(t, unix.ENOENT, unix.ENOENT, unix.ENOENT)
	e := newBlockedSetWireTestEngine(t, conn)
	e.cfg.DenyTempIPLimit = 1
	e.liveBlockCounts = func() (int, int, error) { return 1, 1, nil }
	e.liveBlockLookup = func(*nftables.Set, []byte) (bool, error) { return true, nil }
	now := time.Now()
	writeRawFirewallState(t, e, FirewallState{Blocked: []BlockedEntry{
		{IP: "192.0.2.23", Reason: "expiring replacement", BlockedAt: now},
		{IP: "192.0.2.24", Reason: "expiring victim", BlockedAt: now, ExpiresAt: now.Add(time.Minute)},
	}})

	if err := e.BlockIPForce("192.0.2.23", "replace with temp", 2*time.Hour); err != nil {
		t.Fatalf("BlockIPForce after both deletes became stale: %v", err)
	}
	if sends() != 4 {
		t.Fatalf("netlink sends = %d, want initial batch plus three bounded retries", sends())
	}
	state := readRawFirewallState(t, e)
	if len(state.Blocked) != 1 || state.Blocked[0].IP != "192.0.2.23" || state.Blocked[0].ExpiresAt.IsZero() {
		t.Fatalf("state after both expired = %+v, want only replacement temporary block", state.Blocked)
	}
}

func TestGuardedOperatorBlockRefusesPermanentDowngrade(t *testing.T) {
	for _, ip := range []string{"192.0.2.110", "2001:db8::110"} {
		t.Run(ip, func(t *testing.T) {
			conn, captured := nftConnCapturingRules(t)
			e := newBlockedSetWireTestEngine(t, conn)
			prior := FirewallState{Blocked: []BlockedEntry{{IP: ip, Reason: "operator deny", BlockedAt: time.Now()}}}
			writeRawFirewallState(t, e, prior)
			guard, ok := interface{}(e).(interface {
				BlockIPForcePreserveLifetime(string, string, time.Duration) error
			})
			if !ok {
				t.Fatal("no atomic permanent-block guard for operator actions")
			}
			if err := guard.BlockIPForcePreserveLifetime(ip, "timed operator block", 24*time.Hour); err == nil {
				t.Fatal("permanent block downgraded")
			}
			state := readRawFirewallState(t, e)
			if len(state.Blocked) != 1 || !state.Blocked[0].ExpiresAt.IsZero() || state.Blocked[0].Reason != "operator deny" {
				t.Fatalf("state changed: %+v", state.Blocked)
			}
			if len(*captured) != 0 {
				t.Fatal("refused downgrade reached the kernel")
			}
		})
	}
}

func TestRestoreBlockRejectsSupersedingDecision(t *testing.T) {
	conn, captured := nftConnCapturingRules(t)
	e := newBlockedSetWireTestEngine(t, conn)
	expected := BlockedEntry{IP: "192.0.2.111", Reason: "bulk block", BlockedAt: time.Now()}
	newer := expected
	newer.Reason = "later operator block"
	writeRawFirewallState(t, e, FirewallState{Blocked: []BlockedEntry{newer}})
	restorer, ok := interface{}(e).(interface {
		RestoreBlockIfUnchanged(string, *BlockedEntry, *BlockedEntry) error
	})
	if !ok {
		t.Fatal("undo has no atomic firewall comparison")
	}
	if err := restorer.RestoreBlockIfUnchanged(expected.IP, &expected, nil); err == nil {
		t.Fatal("stale undo removed newer block")
	}
	got := readRawFirewallState(t, e)
	if len(got.Blocked) != 1 || got.Blocked[0].Reason != newer.Reason {
		t.Fatalf("newer block lost: %+v", got.Blocked)
	}
	if len(*captured) != 0 {
		t.Fatal("stale undo reached kernel")
	}
}

func TestGuardedOperatorBlockChecksUntrackedKernelLifetime(t *testing.T) {
	for _, kind := range []string{"absent", "temporary", "permanent", "unavailable"} {
		t.Run(kind, func(t *testing.T) {
			conn, captured := nftConnCapturingRules(t)
			e := newBlockedSetWireTestEngine(t, conn)
			const ip = "192.0.2.112"
			writeRawFirewallState(t, e, FirewallState{})
			e.liveBlockedDump = func(*nftables.Set) ([]nftables.SetElement, error) {
				switch kind {
				case "absent":
					return nil, nil
				case "unavailable":
					return nil, errors.New("netlink unavailable")
				case "temporary":
					return []nftables.SetElement{{Key: net.ParseIP(ip).To4(), Expires: time.Hour}}, nil
				default:
					return []nftables.SetElement{{Key: net.ParseIP(ip).To4()}}, nil
				}
			}
			e.liveBlockLookup = func(*nftables.Set, []byte) (bool, error) { return kind != "absent", nil }
			err := e.BlockIPForcePreserveLifetime(ip, "operator 24h", 24*time.Hour)
			refuse := kind == "permanent" || kind == "unavailable"
			if (err != nil) != refuse {
				t.Fatalf("error=%v refuse=%v", err, refuse)
			}
			if refuse {
				if len(*captured) != 0 || len(readRawFirewallState(t, e).Blocked) != 0 {
					t.Fatal("refused block changed firewall")
				}
			} else {
				state := readRawFirewallState(t, e)
				if len(state.Blocked) != 1 || state.Blocked[0].ExpiresAt.IsZero() {
					t.Fatalf("timed block missing: %+v", state.Blocked)
				}
			}
		})
	}
}

func TestRestoreBlockPreservesPriorDeadline(t *testing.T) {
	sink := withActionSink(t)
	conn, _ := nftConnCapturingRules(t)
	e := newBlockedSetWireTestEngine(t, conn)
	expected := BlockedEntry{IP: "192.0.2.113", Reason: "bulk permanent", BlockedAt: time.Now()}
	prior := BlockedEntry{IP: expected.IP, Reason: "original timed block", ExpiresAt: time.Now().Add(time.Hour)}
	writeRawFirewallState(t, e, FirewallState{Blocked: []BlockedEntry{expected}})
	if err := e.RestoreBlockIfUnchanged(expected.IP, &expected, &prior); err != nil {
		t.Fatal(err)
	}
	if len(sink.records) != 1 || sink.records[0].Target != prior.IP {
		t.Fatalf("restored block missing from unified action log: %+v", sink.records)
	}
	got := readRawFirewallState(t, e).Blocked
	if len(got) != 1 || got[0].Reason != prior.Reason || got[0].ExpiresAt.Sub(prior.ExpiresAt).Abs() > time.Second {
		t.Fatalf("deadline changed: %+v", got)
	}
}

func TestBulkBlockSnapshotsComeFromTheMutation(t *testing.T) {
	conn, _ := nftConnCapturingRules(t)
	e := newBlockedSetWireTestEngine(t, conn)
	original := BlockedEntry{IP: "192.0.2.114", Reason: "original", BlockedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour)}
	writeRawFirewallState(t, e, FirewallState{Blocked: []BlockedEntry{original}})
	blocker, ok := interface{}(e).(interface {
		BlockIPForUndo(string, string, time.Duration) (*BlockedEntry, *BlockedEntry, error)
		UnblockIPForUndo(string) (*BlockedEntry, error)
	})
	if !ok {
		t.Fatal("bulk actions cannot capture their own atomic snapshots")
	}
	before, after, err := blocker.BlockIPForUndo(original.IP, "bulk permanent", 0)
	if err != nil {
		t.Fatal(err)
	}
	if before == nil || !SameBlockedEntry(*before, original) || after == nil || !after.ExpiresAt.IsZero() {
		t.Fatalf("wrong snapshots: before=%+v after=%+v", before, after)
	}
	if err = e.BlockIPForce(original.IP, "later decision", 0); err != nil {
		t.Fatal(err)
	}
	if err = e.RestoreBlockIfUnchanged(original.IP, after, before); !errors.Is(err, ErrBlockChanged) {
		t.Fatalf("later decision overwritten: %v", err)
	}
	removed, err := blocker.UnblockIPForUndo(original.IP)
	if err != nil || removed == nil || removed.Reason != "later decision" {
		t.Fatalf("unblock snapshot: %+v err=%v", removed, err)
	}
}
