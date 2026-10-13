//go:build linux

package firewall

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/nftables"
)

// Recovery needs a current snapshot proof without changing saved or live
// effects, even when a state repair changed nothing.
func TestProbeBlockStateProvesSnapshotWithoutDispatch(t *testing.T) {
	for _, fault := range []string{"none", "held", "dump", "corrupt"} {
		t.Run(fault, func(t *testing.T) {
			f := newBatchFixture(t, FirewallState{Blocked: []BlockedEntry{{IP: "192.0.2.10", ActionID: "act_unknown", Unverified: true}}})
			path := filepath.Join(f.e.statePath, "state.json")
			var want error
			wantDumps := 2
			switch fault {
			case "held":
				want = ErrBlockBatchState
				f.e.blockBatchStateErr = errors.Join(want, errors.New("state write failed"))
				wantDumps = 0
			case "dump":
				want = errors.New("blocked set unavailable")
				f.err = want
				wantDumps = 1
			case "corrupt":
				want = ErrBlockBatchState
				if err := os.WriteFile(path, []byte("{broken"), 0o600); err != nil {
					t.Fatal(err)
				}
				wantDumps = 0
			}
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			dumps := 0
			original := f.e.liveBlockedDump
			f.e.liveBlockedDump = func(set *nftables.Set) ([]nftables.SetElement, error) {
				dumps++
				return original(set)
			}
			if probeErr := f.e.ProbeBlockState(); !errors.Is(probeErr, want) {
				t.Fatalf("probe = %v, want %v", probeErr, want)
			}
			if fault == "corrupt" {
				// The loader preserves corrupt input; a probe must not replace
				// it with an empty desired state or send anything to the kernel.
				if _, statErr := os.Stat(path); !errors.Is(statErr, os.ErrNotExist) {
					t.Fatalf("corrupt input was not set aside: %v", statErr)
				}
				path = f.e.StateSetAside()
				if path == "" {
					t.Fatal("corrupt input has no preserved copy")
				}
			}
			after, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if dumps != wantDumps || f.sends != 0 || !bytes.Equal(before, after) {
				t.Fatalf("probe mutated or skipped state: dumps=%d want=%d sends=%d unchanged=%v", dumps, wantDumps, f.sends, bytes.Equal(before, after))
			}
		})
	}
}

// A snapshot keys its rows by canonical address once, so each member check
// is a lookup, and a row written in another spelling still matches.
func TestBlockSnapshotKeysRowsByCanonicalAddress(t *testing.T) {
	f := newBatchFixture(t, FirewallState{
		Blocked:     []BlockedEntry{{IP: "2001:DB8::10", Reason: "operator"}},
		Allowed:     []AllowedEntry{{IP: "2001:0db8::20", Reason: "operator"}},
		PortAllowed: []PortAllowEntry{{IP: "203.0.113.30", Port: 22, Proto: "tcp"}},
	})
	f.e.mu.Lock()
	snap, err := f.e.blockSnapshotLocked()
	f.e.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if !snap.blocked["2001:db8::10"] || !snap.allowed["2001:db8::20"] || !snap.allowed["203.0.113.30"] {
		t.Fatalf("snapshot keys: blocked %v, allowed %v", snap.blocked, snap.allowed)
	}
	got, err := f.e.CheckBlockBatch([]BlockMember{
		f.member("act_blocked", "2001:db8::10"),
		f.member("act_allowed", "2001:db8::20"),
		f.member("act_port", "203.0.113.30"),
		f.member("act_free", "2001:db8::40"),
	})
	want := []BlockRefusal{BlockRefusedExisting, BlockRefusedAllowed, BlockRefusedAllowed, ""}
	if err != nil || fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("answers %q, %v; want %q", got, err, want)
	}
}

// A full batch against a large state: 3,000 timed blocks and 500 allows.
// It measures and does not gate.
func BenchmarkCheckBlockBatchLargeState(b *testing.B) {
	at := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)
	var state FirewallState
	for i := 0; i < 3000; i++ {
		state.Blocked = append(state.Blocked, BlockedEntry{IP: fmt.Sprintf("2001:db8:1::%x", i+1), Reason: "bench", ExpiresAt: at.Add(time.Hour)})
	}
	for i := 0; i < 500; i++ {
		state.Allowed = append(state.Allowed, AllowedEntry{IP: fmt.Sprintf("2001:db8:2::%x", i+1), Reason: "bench"})
	}
	f := newBatchFixture(b, state)
	members := make([]BlockMember, MaxBlockBatchMembers)
	for i := range members {
		members[i] = f.member(fmt.Sprintf("act_%d", i), fmt.Sprintf("2001:db8:3::%x", i+1))
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := f.e.CheckBlockBatch(members); err != nil {
			b.Fatal(err)
		}
	}
}

func TestBlockSnapshotKeysPreserveAddressEquality(t *testing.T) {
	for _, tc := range []struct{ name, row, member string }{
		{"mapped", "::ffff:192.0.2.10", "192.0.2.10"},
		{"expanded", "2001:0DB8:0:0:0:0:0:10", "2001:db8::10"},
		{"zone", "2001:db8::10%eth0", "2001:db8::10"},
		{"invalid", "192.0.2.010", "192.0.2.10"},
		{"garbage", "invalid", "192.0.2.10"},
	} {
		for _, source := range []string{"blocked", "allowed", "port"} {
			t.Run(tc.name+"/"+source, func(t *testing.T) {
				var state FirewallState
				switch source {
				case "blocked":
					state.Blocked = []BlockedEntry{{IP: tc.row, Reason: "operator"}}
				case "allowed":
					state.Allowed = []AllowedEntry{{IP: tc.row, Reason: "operator"}}
				case "port":
					state.PortAllowed = []PortAllowEntry{{IP: tc.row, Port: 22, Proto: "tcp"}}
				}
				f := newBatchFixture(t, state)
				f.e.mu.Lock()
				snap, err := f.e.blockSnapshotLocked()
				f.e.mu.Unlock()
				if err != nil {
					t.Fatal(err)
				}
				indexed := snap.allowed[stateIPKey(tc.member)]
				if source == "blocked" {
					indexed = snap.blocked[stateIPKey(tc.member)]
				}
				equal := sameIPString(tc.row, tc.member)
				if indexed != equal {
					t.Fatalf("index match %v, old equality %v", indexed, equal)
				}
				got, err := f.e.CheckBlockBatch([]BlockMember{f.member("act_member", tc.member)})
				var want BlockRefusal
				if equal {
					want = BlockRefusedAllowed
					if source == "blocked" {
						want = BlockRefusedExisting
					}
				}
				if err != nil || len(got) != 1 || got[0] != want {
					t.Fatalf("check: %v %v, want %q", got, err, want)
				}
			})
		}
	}
}
