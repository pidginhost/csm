//go:build linux

package firewall

import (
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/google/nftables"
)

// A lease ahead of wall time must not put expired rows into the snapshot
// while kernel planning correctly omits them from its desired sets.
func TestPrepareFirewallUndoUsesLeaseClock(t *testing.T) {
	wall := time.Now().Round(0)
	lease := wall.Add(2 * time.Hour)
	e := newBlockedSetWireTestEngine(t, leaseActionReadConn(t, nil))
	e.expiryClock = func() time.Time { return wall }
	e.leaseClock = func() (time.Time, time.Time) { return lease, lease }
	want := FirewallState{
		Blocked:     []BlockedEntry{{IP: "203.0.113.82", ExpiresAt: lease.Add(time.Hour), Unverified: true}, {IP: "203.0.113.83"}},
		Allowed:     []AllowedEntry{{IP: "192.0.2.81", ExpiresAt: lease.Add(time.Hour)}, {IP: "192.0.2.82"}},
		BlockedNet:  []SubnetEntry{{CIDR: "198.51.100.16/28", ExpiresAt: lease.Add(time.Hour)}, {CIDR: "198.51.100.32/28"}},
		PortAllowed: []PortAllowEntry{{IP: "192.0.2.83", Port: 443, Proto: "tcp"}},
	}
	plan := FirewallAction{Request: ActionRequest{Operation: "undo"}, After: FirewallState{
		Blocked:     append([]BlockedEntry{{IP: "203.0.113.80", ExpiresAt: wall.Add(time.Hour)}, {IP: "203.0.113.81", ExpiresAt: lease, Unverified: true}}, want.Blocked...),
		Allowed:     append([]AllowedEntry{{IP: "192.0.2.80", ExpiresAt: wall.Add(time.Hour)}}, want.Allowed...),
		BlockedNet:  append([]SubnetEntry{{CIDR: "198.51.100.0/28", ExpiresAt: wall.Add(time.Hour)}}, want.BlockedNet...),
		PortAllowed: want.PortAllowed,
	}}
	if err := (engineActionKernel{e}).PrepareFirewallUndo(&plan); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(plan.After, want) || !plan.CreatedAt.Equal(lease) {
		t.Fatalf("undo planned beyond lease expiry: %#v at %v", plan.After, plan.CreatedAt)
	}
}

type undoMemberPlanStore struct {
	*batchPlanStore
	batch FirewallAction
}

func (s undoMemberPlanStore) ReadFirewallBatchMember(string) (FirewallAction, error) {
	return s.batch, nil
}

// A backward wall step must not make an expired alias prevent member undo.
// Live and unverified aliases still prevent it before admission.
func TestMemberUndoChecksAliasesOnLeaseClock(t *testing.T) {
	for _, kind := range []string{"expired", "live", "unverified"} {
		t.Run(kind, func(t *testing.T) {
			wall := time.Now().Round(0)
			lease := wall.Add(2 * time.Hour)
			member := batchMember("member-a", "203.0.113.80")
			other := batchMember("member-b", "203.0.113.81")
			rows := []BlockedEntry{
				{IP: member.Target, ActionID: member.ID, Reason: member.Reason, BlockedAt: lease, ExpiresAt: lease.Add(member.TTL)},
				{IP: other.Target, ActionID: other.ID, Reason: other.Reason, BlockedAt: lease, ExpiresAt: lease.Add(other.TTL)},
			}
			batch := FirewallAction{Request: batchHeader(), Members: []ActionMember{{Request: member}, {Request: other}}, After: FirewallState{Blocked: rows}, CreatedAt: lease, Phase: "verified"}
			alias := BlockedEntry{IP: "::ffff:203.0.113.80", ExpiresAt: wall.Add(time.Hour), Unverified: kind == "unverified"}
			if kind == "live" {
				alias.ExpiresAt = lease.Add(time.Hour)
			}
			state := FirewallState{Blocked: append([]BlockedEntry{alias}, rows...)}
			var elements []nftables.SetElement
			for _, row := range rows {
				_, key, _ := blockedSetKey(row.IP, false)
				elements = append(elements, nftables.SetElement{Key: key, Comment: stateFingerprint(row), Timeout: time.Hour, Expires: time.Hour})
			}
			e := newBlockedSetWireTestEngine(t, leaseActionReadConn(t, elements))
			e.expiryClock = func() time.Time { return wall }
			e.leaseClock = func() (time.Time, time.Time) { return lease, lease }
			s := undoMemberPlanStore{batchPlanStore: &batchPlanStore{state: state}, batch: batch}
			if err := e.AttachLifecycle(&Lifecycle{Store: s}); err != nil {
				t.Fatal(err)
			}
			_, err := e.UndoAction(ActionRequest{ID: "undo-member-a", Operation: "undo", Actor: "cli", Source: "cli", UndoOf: member.ID})
			if kind != "expired" {
				if !errors.Is(err, ErrStateConflict) || len(s.admitted) != 0 {
					t.Fatalf("conflicting alias reached admission: %d plans, %v", len(s.admitted), err)
				}
				return
			}
			if !errors.Is(err, errBatchPlanStop) || len(s.admitted) != 1 {
				t.Fatalf("expired alias prevented undo planning: %d plans, %v", len(s.admitted), err)
			}
			plan := s.admitted[0]
			want := FirewallState{Blocked: rows[1:]}
			if !reflect.DeepEqual(plan.Before, state) || !reflect.DeepEqual(plan.After, want) || !plan.CreatedAt.Equal(lease) {
				t.Fatalf("undo changed surviving rows or planning time: %#v", plan)
			}
			if err := (engineActionKernel{e}).ValidateEvidence(plan); err != nil {
				t.Fatalf("undo evidence: %v", err)
			}
		})
	}
}
