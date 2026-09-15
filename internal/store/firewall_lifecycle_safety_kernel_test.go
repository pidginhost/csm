//go:build linux && nftkernel

package store

import (
	"errors"
	"testing"
	"time"

	"github.com/google/nftables"
	"github.com/pidginhost/csm/internal/firewall"
)

func TestKernelDurablePlanningKeepsSafetySnapshot(t *testing.T) {
	for _, operation := range []string{"subnet", "automatic IP"} {
		for _, failRead := range []bool{false, true} {
			name := operation + "/changed revision"
			if failRead {
				name = operation + "/failed read"
			}
			t.Run(name, func(t *testing.T) {
				lifecycleNamespace(t)
				db := openSnapshotDB(t)
				if _, err := db.ReplaceFirewallState(0, firewall.FirewallState{}); err != nil {
					t.Fatal(err)
				}
				s := &changingPlanningStore{DB: db}
				e, err := firewall.NewEngine(&firewall.FirewallConfig{Enabled: true, IPv6: true}, t.TempDir())
				if err != nil {
					t.Fatal(err)
				}
				if err := e.AttachLifecycle(&firewall.Lifecycle{Store: s, Audit: func(firewall.FirewallAction) error { return nil }}); err != nil {
					t.Fatal(err)
				}
				if err := e.Apply(); err != nil {
					t.Fatal(err)
				}
				s.admitted = nil
				// Introduce an operator allow just after the locked safety check reads
				// its snapshot. Later reads must not legitimize that stale decision.
				readsUntilSafety := 2
				if operation == "automatic IP" {
					readsUntilSafety = 6
				}
				changed := false
				readFailure := errors.New("safety snapshot unavailable")
				var hook func(firewall.FirewallState, uint64) error
				hook = func(state firewall.FirewallState, revision uint64) error {
					readsUntilSafety--
					if readsUntilSafety > 0 {
						s.onRead = hook
						return nil
					}
					state.PortAllowed = append(state.PortAllowed, firewall.PortAllowEntry{IP: "192.0.2.183", Port: 443, Proto: "tcp", Reason: "operator policy"})
					if _, err := db.ReplaceFirewallState(revision, state); err != nil {
						t.Fatal(err)
					}
					changed = true
					if failRead {
						return readFailure
					}
					return nil
				}
				s.onRead = hook
				if operation == "subnet" {
					err = e.BlockSubnetRequest(firewall.ActionRequest{ID: "stale-safety", Target: "192.0.2.0/24", TTL: time.Hour}, nil)
				} else {
					_, err = e.BlockIPRequest(firewall.ActionRequest{ID: "stale-safety", Target: "192.0.2.183", TTL: time.Hour, Automatic: true}, nil)
				}
				if !changed {
					t.Fatal("safety read was not exercised")
				}
				want := firewall.ErrStateConflict
				if failRead {
					want = readFailure
				}
				if !errors.Is(err, want) {
					t.Errorf("unsafe planning result = %v, want %v", err, want)
				}
				if len(s.admitted) != 0 {
					t.Errorf("unsafe plan admitted: %d actions", len(s.admitted))
				}
				state, _, err := db.ReadFirewallState()
				if err != nil {
					t.Fatal(err)
				}
				if len(state.Blocked) != 0 || len(state.BlockedNet) != 0 || len(state.PortAllowed) != 1 {
					t.Errorf("safety invariant lost: %+v", state)
				}
				if live, err := e.IsBlockedLive("192.0.2.183"); err != nil || live {
					t.Errorf("protected address blocked = %v, error = %v", live, err)
				}
			})
		}
	}
}

func TestKernelDurableNoopRemovalRefusesLiveDrift(t *testing.T) {
	for _, operation := range []string{"unblock", "flush", "remove_allow", "remove_allow_source", "unblock_subnet"} {
		t.Run(operation, func(t *testing.T) {
			db, e, _ := durableKernelEngine(t)
			remove := func() error {
				switch operation {
				case "unblock":
					return e.UnblockIP("192.0.2.184")
				case "flush":
					return e.FlushBlocked()
				case "remove_allow":
					return e.RemoveAllowIP("192.0.2.184")
				case "remove_allow_source":
					return e.RemoveAllowIPBySource("192.0.2.184", "cli")
				default:
					return e.UnblockSubnet("192.0.2.0/24")
				}
			}
			if err := remove(); err != nil {
				t.Fatalf("removal of an absent target failed: %v", err)
			}
			conn := &nftables.Conn{}
			setName := "blocked_ips"
			if operation == "remove_allow" || operation == "remove_allow_source" {
				setName = "allowed_ips"
			}
			if operation == "unblock_subnet" {
				setName = "blocked_nets"
			}
			set, err := conn.GetSetByName(&nftables.Table{Name: "csm", Family: nftables.TableFamilyINet}, setName)
			if err != nil {
				t.Fatal(err)
			}
			elements := []nftables.SetElement{{Key: []byte{192, 0, 2, 184}}}
			if operation == "unblock_subnet" {
				elements = []nftables.SetElement{{Key: []byte{192, 0, 2, 0}}, {Key: []byte{192, 0, 3, 0}, IntervalEnd: true}}
			}
			if err := conn.SetAddElements(set, elements); err != nil {
				t.Fatal(err)
			}
			if err := conn.Flush(); err != nil {
				t.Fatal(err)
			}
			_, revision, err := db.ReadFirewallState()
			if err != nil {
				t.Fatal(err)
			}
			err = remove()
			if !errors.Is(err, firewall.ErrActionUnknown) {
				t.Errorf("untracked live policy reported as removed: %v", err)
			}
			_, afterRevision, err := db.ReadFirewallState()
			if err != nil || revision != afterRevision {
				t.Errorf("drift accepted: revision %d -> %d, err %v", revision, afterRevision, err)
			}
		})
	}
}
