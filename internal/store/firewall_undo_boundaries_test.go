package store

import (
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/firewall"
)

// D12 applies to all inverse operations, including metadata and batch undo.
func TestFirewallUndoExpiryAcrossOperations(t *testing.T) {
	for _, op := range []string{"block", "unblock", "allow", "remove_allow", "block_subnet", "unblock_subnet", "flush", "state", "undo"} {
		t.Run(op, func(t *testing.T) {
			db := openSnapshotDB(t)
			at := time.Now().UTC().Round(0)
			expired := at.Add(-time.Hour)
			live := at.Add(time.Hour)
			before := firewall.FirewallState{
				Blocked:     []firewall.BlockedEntry{{IP: "192.0.2.1", ExpiresAt: expired}, {IP: "192.0.2.2", ExpiresAt: expired, Unverified: true}, {IP: "192.0.2.3", ExpiresAt: live, Unverified: true}},
				Allowed:     []firewall.AllowedEntry{{IP: "192.0.2.4", ExpiresAt: expired}, {IP: "192.0.2.5", ExpiresAt: live}, {IP: "192.0.2.6"}},
				BlockedNet:  []firewall.SubnetEntry{{CIDR: "198.51.100.0/28", ExpiresAt: expired}, {CIDR: "198.51.100.16/28", ExpiresAt: live}, {CIDR: "198.51.100.32/28"}},
				PortAllowed: []firewall.PortAllowEntry{{IP: "192.0.2.7", Port: 443, Proto: "tcp"}},
			}
			if _, err := db.ReplaceFirewallState(0, before); err != nil {
				t.Fatal(err)
			}
			k := &observedKernel{state: before}
			l := lifecycleFor(t, db, func(firewall.FirewallAction) error { return nil })
			a := firewall.FirewallAction{Request: firewall.ActionRequest{ID: "original", Operation: op, Target: "192.0.2.8", Actor: "cli"}, Before: before, Revision: 1, CreatedAt: at}
			if _, err := l.Execute(a, k); err != nil {
				t.Fatal(err)
			}
			if _, err := l.Undo(undoOf("inverse", "original"), k); err != nil {
				t.Fatal(err)
			}
			want := firewall.FirewallState{Blocked: before.Blocked[2:], Allowed: before.Allowed[1:], BlockedNet: before.BlockedNet[1:], PortAllowed: before.PortAllowed}
			got, rev, err := db.ReadFirewallState()
			if err != nil || rev != 3 || !reflect.DeepEqual(got, want) || !reflect.DeepEqual(k.state, want) {
				t.Fatalf("undo expiry result: %#v rev %d err %v", got, rev, err)
			}
		})
	}
}

func TestFirewallMemberUndoCleansAllExpiredRows(t *testing.T) {
	for _, member := range []bool{false, true} {
		t.Run(map[bool]string{false: "whole batch", true: "one member"}[member], func(t *testing.T) {
			db := openSnapshotDB(t)
			l := lifecycleFor(t, db, func(firewall.FirewallAction) error { return nil })
			k := &observedKernel{}
			at := time.Now().UTC().Round(0)
			expired := firewall.BlockedEntry{IP: "198.51.100.44", ExpiresAt: at.Add(-time.Hour)}
			a := liveBatch(t, db, l, k, expired)
			target := a.Request.ID
			want := a.Before
			want.Blocked = want.Blocked[:1:1]
			if member {
				target = "member-1"
				later := runLater(t, db, l, k, "later", func(s *firewall.FirewallState) {
					s.Blocked = append(s.Blocked, firewall.BlockedEntry{IP: "::ffff:203.0.113.20", ExpiresAt: at.Add(-time.Hour)}, firewall.BlockedEntry{IP: "198.51.100.45", ExpiresAt: at.Add(-time.Hour), Unverified: true})
					s.Allowed = []firewall.AllowedEntry{{IP: "192.0.2.5", ExpiresAt: at.Add(-time.Hour)}}
					s.BlockedNet = []firewall.SubnetEntry{{CIDR: "198.51.100.0/28", ExpiresAt: at.Add(-time.Hour)}}
				})
				want.Blocked = append(want.Blocked, later.After.Blocked[3])
			}
			if _, err := l.Undo(undoOf("inverse", target), k); err != nil {
				t.Fatal(err)
			}
			got, _, err := db.ReadFirewallState()
			if err != nil || !reflect.DeepEqual(got, want) {
				t.Fatalf("expired rows retained: %#v; want %#v, %v", got, want, err)
			}
		})
	}
}

// A member undo still needs fresh complete kernel proof before any mutation.
func TestFirewallMemberUndoRefusesKernelDrift(t *testing.T) {
	db := openSnapshotDB(t)
	l := lifecycleFor(t, db, func(firewall.FirewallAction) error { return nil })
	k := &observedKernel{}
	a := liveBatch(t, db, l, k)
	k.state = firewall.FirewallState{}
	writes := k.writes
	if _, err := l.Undo(undoOf("inverse", "member-1"), k); !errors.Is(err, firewall.ErrActionUnknown) {
		t.Fatalf("kernel drift = %v", err)
	}
	if k.writes != writes {
		t.Fatal("undo wrote a drifted kernel")
	}
	assertFirewallSnapshot(t, db, a.After, 2)
}
