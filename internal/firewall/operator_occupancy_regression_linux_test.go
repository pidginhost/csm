//go:build linux

package firewall

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"syscall"
	"testing"
	"time"

	"github.com/google/nftables"
)

func TestOperatorOccupancyFallbackIgnoresDisabledIPv6(t *testing.T) {
	for _, mode := range []string{"live", "dump failure", "no transport"} {
		t.Run(mode, func(t *testing.T) {
			f := newBatchFixture(t, FirewallState{})
			f.e.cfg.IPv6, f.e.setBlocked6 = false, nil
			state := FirewallState{Blocked: []BlockedEntry{
				{IP: "203.0.113.90", ActionID: "act_owned", ExpiresAt: f.at.Add(time.Hour)},
				{IP: "2001:db8::91", ExpiresAt: f.at.Add(time.Hour)},
				{IP: "::ffff:203.0.113.92", ExpiresAt: f.at.Add(time.Hour)},
			}}
			f.live["203.0.113.90"], f.live["203.0.113.92"] = time.Hour, time.Hour
			switch mode {
			case "dump failure":
				f.err = errors.New("dump unavailable")
			case "no transport":
				f.e.liveBlockedDump, f.e.conn = nil, nil
			}
			f.e.mu.Lock()
			got := f.e.operatorTempCountLocked(state, "")
			f.e.mu.Unlock()
			if got != 1 {
				t.Fatalf("non-admission IPv4 occupants = %d, want 1", got)
			}
		})
	}
}

func TestOperatorBlockSkipsInactiveVictims(t *testing.T) {
	for _, inactive := range []string{"expired", "disabled IPv6", "expired admission alias"} {
		t.Run(inactive, func(t *testing.T) {
			f := newBatchFixture(t, FirewallState{})
			f.e.cfg.IPv6, f.e.setBlocked6 = false, nil
			f.e.cfg.DenyTempIPLimit = 1
			old := BlockedEntry{IP: "203.0.113.89", ExpiresAt: f.at.Add(-time.Hour)}
			if inactive == "disabled IPv6" {
				old.IP, old.ExpiresAt = "2001:db8::89", f.at.Add(time.Minute)
			}
			state := FirewallState{Blocked: []BlockedEntry{
				{IP: "203.0.113.90", ActionID: "act_owned", ExpiresAt: f.at.Add(time.Hour)},
				{IP: "203.0.113.91", ExpiresAt: f.at.Add(time.Hour)}, old,
			}}
			if inactive == "expired admission alias" {
				f.e.cfg.DenyTempIPLimit = 2
				state.Blocked[2].ActionID = "act_expired"
				state.Blocked = append(state.Blocked, BlockedEntry{IP: "::ffff:203.0.113.89", ExpiresAt: f.at.Add(time.Minute)})
				f.live[old.IP] = time.Minute
			}
			writeRawFirewallState(t, f.e, state)
			f.live["203.0.113.90"], f.live["203.0.113.91"] = time.Hour, time.Hour
			f.e.mu.Lock()
			_, _, _, victim, err := f.e.blockIPTarget("203.0.113.92", time.Hour, false)
			f.e.mu.Unlock()
			if err != nil || victim != "203.0.113.91" {
				t.Fatalf("victim=%q error=%v, want the active IPv4 occupant", victim, err)
			}
		})
	}
}

func TestOperatorBlockPreservesCachedAdmissionAliases(t *testing.T) {
	f := newBatchFixture(t, FirewallState{})
	f.e.cfg.DenyTempIPLimit = 2
	state := FirewallState{Blocked: []BlockedEntry{
		{IP: "203.0.113.90", ActionID: "act_owned", ExpiresAt: f.at.Add(2 * time.Hour)},
		{IP: "::ffff:203.0.113.90", ExpiresAt: f.at.Add(time.Hour)},
		{IP: "203.0.113.91", ExpiresAt: f.at.Add(3 * time.Hour)},
	}}
	writeRawFirewallState(t, f.e, state)
	f.live["203.0.113.90"], f.live["203.0.113.91"] = 2*time.Hour, 3*time.Hour
	f.e.mu.Lock()
	f.e.loadStateFile()
	f.e.mu.Unlock()
	if err := os.WriteFile(filepath.Join(f.e.statePath, "state.json"), []byte("{"), 0600); err != nil {
		t.Fatal(err)
	}
	f.e.mu.Lock()
	_, _, _, victim, err := f.e.blockIPTarget("203.0.113.92", time.Hour, false)
	f.e.mu.Unlock()
	if err != nil || victim != "203.0.113.91" {
		t.Fatalf("cached ownership: victim=%q error=%v, want the non-admission victim", victim, err)
	}
}

func TestOperatorBlockRestoresAdmissionAliasesAfterSyncFailure(t *testing.T) {
	conn, sends := nftConnReturningErrsThenOK(t)
	e := newBlockedSetWireTestEngine(t, conn)
	at := e.expiryNow().UTC()
	before := FirewallState{Blocked: []BlockedEntry{
		{IP: "203.0.113.90", ActionID: "act_owned", ExpiresAt: at.Add(time.Hour)},
		{IP: "::ffff:203.0.113.90", Automatic: true, ExpiresAt: at.Add(2 * time.Hour)},
	}}
	writeRawFirewallState(t, e, before)
	previous := writeFirewallStateJSON
	t.Cleanup(func() { writeFirewallStateJSON = previous })
	writes := 0
	writeFirewallStateJSON = func(path string, perm os.FileMode, state any) error {
		writes++
		if err := previous(path, perm, state); err != nil {
			return err
		}
		if writes == 1 {
			return syscall.EIO
		}
		return nil
	}
	if err := e.BlockIPForce("203.0.113.92", "operator", time.Hour); !errors.Is(err, syscall.EIO) {
		t.Fatalf("block error = %v, want sync failure", err)
	}
	if writes != 2 || sends() != 0 {
		t.Fatalf("writes=%d sends=%d, want intent and rollback without a kernel write", writes, sends())
	}
	if got := readRawFirewallState(t, e); !reflect.DeepEqual(got, before) {
		t.Fatalf("sync rollback changed admission aliases: %+v", got)
	}
}

// Both aliases must survive: merging them either hides an unknown occupant
// or lets eviction of its address delete an admission action's effect.
func TestOperatorBlockPreservesAdmissionAliases(t *testing.T) {
	for _, ownedLonger := range []bool{false, true} {
		for _, reverse := range []bool{false, true} {
			for _, fail := range []bool{false, true} {
				t.Run(fmt.Sprintf("ownedLonger=%t/reverse=%t/fail=%t", ownedLonger, reverse, fail), func(t *testing.T) {
					f := newBatchFixture(t, FirewallState{})
					f.e.cfg.DenyTempIPLimit = 2
					owned := BlockedEntry{IP: "203.0.113.90", ActionID: "act_owned", ExpiresAt: f.at.Add(time.Hour)}
					alias := BlockedEntry{IP: "::ffff:203.0.113.90", Automatic: true, ExpiresAt: f.at.Add(2 * time.Hour)}
					if ownedLonger {
						owned.ExpiresAt, alias.ExpiresAt = alias.ExpiresAt, owned.ExpiresAt
					}
					rows := []BlockedEntry{owned, alias}
					if reverse {
						rows[0], rows[1] = rows[1], rows[0]
					}
					other := BlockedEntry{IP: "203.0.113.91", ExpiresAt: f.at.Add(3 * time.Hour)}
					before := FirewallState{Blocked: append(append([]BlockedEntry(nil), rows...), other)}
					writeRawFirewallState(t, f.e, before)
					f.live[owned.IP], f.live[other.IP] = 2*time.Hour, 3*time.Hour
					f.e.liveBlockLookup = func(_ *nftables.Set, key []byte) (bool, error) {
						_, found := f.live[net.IP(key).String()]
						return found, nil
					}
					f.e.liveBlockCounts = func() (int, int, error) { return 0, 2, nil }
					conn, captured := nftConnCapturingRules(t)
					if fail {
						conn, _ = nftConnReturningErrsThenOK(t, syscall.EPERM)
					}
					f.e.conn = conn
					err := f.e.BlockIPForce("203.0.113.92", "operator", time.Hour)
					if fail {
						if err == nil {
							t.Fatal("kernel failure accepted")
						}
						if got := readRawFirewallState(t, f.e); !reflect.DeepEqual(got, before) {
							t.Fatalf("rollback changed admission aliases: %+v", got)
						}
						return
					}
					if err != nil {
						t.Fatal(err)
					}
					got := readRawFirewallState(t, f.e)
					if len(got.Blocked) != 3 || !reflect.DeepEqual(got.Blocked[:2], rows) || got.Blocked[2].IP != "203.0.113.92" {
						t.Fatalf("operator block lost aliases or evicted the wrong occupant: %+v", got.Blocked)
					}
					if n := delSetElemCount(t, *captured, "blocked_ips"); n != 1 {
						t.Fatalf("kernel deletions = %d, want only the non-admission victim", n)
					}
				})
			}
		}
	}
}
