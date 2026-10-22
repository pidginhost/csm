package store

import (
	"bytes"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/firewall"
)

// A batch only adds its members' rows: nothing evicts for a batch, so its
// After state keeps every row of its Before state that has not expired.
func TestFirewallBatchStatesOnlyAddMemberRows(t *testing.T) {
	row := func(a *firewall.FirewallAction, id string) *firewall.BlockedEntry {
		for i := range a.After.Blocked {
			if a.After.Blocked[i].ActionID == id {
				return &a.After.Blocked[i]
			}
		}
		t.Fatalf("fixture has no row for %s", id)
		return nil
	}
	without := func(rows []firewall.BlockedEntry, ip string) []firewall.BlockedEntry {
		var out []firewall.BlockedEntry
		for _, r := range rows {
			if r.IP != ip {
				out = append(out, r)
			}
		}
		return out
	}
	cases := map[string]func(*firewall.FirewallAction){
		"drops a permanent row":   func(a *firewall.FirewallAction) { a.After.Blocked = without(a.After.Blocked, "192.0.2.1") },
		"changes a kept row":      func(a *firewall.FirewallAction) { a.After.Blocked[1].Reason = "changed" },
		"member without its row":  func(a *firewall.FirewallAction) { a.After.Blocked = without(a.After.Blocked, "203.0.113.11") },
		"row of another action":   func(a *firewall.FirewallAction) { row(a, "member-two").ActionID = "member-three" },
		"row with another reason": func(a *firewall.FirewallAction) { row(a, "member-one").Reason = "other" },
		"row outlives its member": func(a *firewall.FirewallAction) {
			row(a, "member-one").ExpiresAt = row(a, "member-one").ExpiresAt.Add(time.Second)
		},
		"permanent member row": func(a *firewall.FirewallAction) { row(a, "member-one").ExpiresAt = time.Time{} },
		"member row expired": func(a *firewall.FirewallAction) {
			r := row(a, "member-one")
			r.BlockedAt = a.CreatedAt.Add(-2 * time.Hour)
			r.ExpiresAt = a.CreatedAt.Add(-time.Hour)
		},
		"unverified member row":   func(a *firewall.FirewallAction) { row(a, "member-two").Unverified = true },
		"row for another address": func(a *firewall.FirewallAction) { row(a, "member-two").IP = "203.0.113.12" },
		"extra row": func(a *firewall.FirewallAction) {
			extra := *row(a, "member-two")
			extra.IP, extra.ActionID = "203.0.113.12", "member-three"
			a.After.Blocked = append(a.After.Blocked, extra)
		},
		"member row twice": func(a *firewall.FirewallAction) { a.After.Blocked = append(a.After.Blocked, *row(a, "member-two")) },
		"mapped target already blocked": func(a *firewall.FirewallAction) {
			held := *row(a, "member-two")
			held.IP, held.ActionID = "::ffff:203.0.113.11", "earlier"
			a.Before.Blocked = append(a.Before.Blocked, held)
			a.After.Blocked = append(a.After.Blocked, held)
		},
		"target already blocked": func(a *firewall.FirewallAction) {
			held := *row(a, "member-two")
			held.ActionID, held.Reason = "", "earlier"
			a.Before.Blocked = append(a.Before.Blocked, held)
			a.After.Blocked = append(a.After.Blocked, held)
		},
		"changes a subnet": func(a *firewall.FirewallAction) { a.After.BlockedNet = nil },
		"changes an allow": func(a *firewall.FirewallAction) { a.After.Allowed = a.After.Allowed[1:] },
		"changes a port allow": func(a *firewall.FirewallAction) {
			a.After.PortAllowed = append(a.After.PortAllowed, firewall.PortAllowEntry{IP: "192.0.2.80", Port: 22, Proto: "tcp", Reason: "added"})
		},
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			db := openSnapshotDB(t)
			in := batchFixture()
			change(&in)
			if _, err := db.ReplaceFirewallState(0, in.Before); err != nil {
				t.Fatal(err)
			}
			image := batchIndexImage(t, db)
			if _, _, err := db.AdmitFirewallAction(in); err == nil || errors.Is(err, firewall.ErrStateConflict) || errors.Is(err, firewall.ErrStateCorrupt) || errors.Is(err, firewall.ErrScanBudget) {
				t.Fatalf("batch state change admitted or refused for another reason: %v", err)
			}
			if after := batchIndexImage(t, db); !bytes.Equal(after, image) {
				t.Fatal("refused batch changed journal or indexes")
			}
			if count, err := db.ReadFirewallScanBudget("2026-01-02T03"); err != nil || count != 0 {
				t.Fatalf("refused batch charged %d, %v", count, err)
			}
		})
	}
	t.Run("drops an expired row", func(t *testing.T) {
		db := openSnapshotDB(t)
		in := batchFixture()
		in.After.Blocked = without(in.After.Blocked, "203.0.113.90")
		if a := admitFixture(t, db, in); len(a.After.Blocked) != len(in.After.Blocked) {
			t.Fatalf("admitted After = %#v", a.After.Blocked)
		}
	})
}

// A one-request action keeps its free-form state change: the batch rule
// applies only to batches of two or more members.
func TestFirewallBatchStatesLeaveOneRequestActions(t *testing.T) {
	db := openSnapshotDB(t)
	in := admissionFixture()
	if len(in.After.Blocked) >= len(in.Before.Blocked) {
		t.Fatal("fixture must remove a row")
	}
	admitFixture(t, db, in)
}

// batchMemberRow is the row a batch member adds: its address, action and
// reason, blocked when the batch was planned, for exactly its TTL.
func batchMemberRow(a firewall.FirewallAction, m firewall.ActionMember) firewall.BlockedEntry {
	return firewall.BlockedEntry{IP: m.Request.Target, Reason: m.Request.Reason, Source: "scan", BlockedAt: a.CreatedAt, ExpiresAt: a.CreatedAt.Add(m.Request.TTL), ActionID: m.Request.ID}
}

func copyFirewallStateForTest(s firewall.FirewallState) firewall.FirewallState {
	return firewall.FirewallState{Blocked: slices.Clone(s.Blocked), BlockedNet: slices.Clone(s.BlockedNet), Allowed: slices.Clone(s.Allowed), PortAllowed: slices.Clone(s.PortAllowed)}
}
