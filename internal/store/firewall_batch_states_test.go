package store

import (
	"bytes"
	"errors"
	"reflect"
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
		"drops a permanent row": func(a *firewall.FirewallAction) { a.After.Blocked = without(a.After.Blocked, "192.0.2.1") },
		"changes a kept row":    func(a *firewall.FirewallAction) { a.After.Blocked[1].Reason = "changed" },
		"reorders kept aliases": func(a *firewall.FirewallAction) {
			other := a.Before.Blocked[1]
			other.IP, other.Reason = "::ffff:192.0.2.1", "later decision"
			other.ExpiresAt = a.CreatedAt.Add(time.Hour)
			a.Before.Blocked = append(a.Before.Blocked, other)
			a.After.Blocked = append(a.After.Blocked, other)
			last := len(a.After.Blocked) - 1
			a.After.Blocked[1], a.After.Blocked[last] = a.After.Blocked[last], a.After.Blocked[1]
		},
		"moves an expired row after a kept row": func(a *firewall.FirewallAction) {
			a.After.Blocked = append(slices.Clone(a.After.Blocked[1:]), a.Before.Blocked[0])
		},
		"drops a row before a kept row": func(a *firewall.FirewallAction) {
			later := a.Before.Blocked[1]
			later.IP, later.Reason = "192.0.2.2", "kept"
			a.Before.Blocked = append(a.Before.Blocked, later)
			a.After.Blocked = append(without(a.After.Blocked, "192.0.2.1"), later)
		},
		"drops an expired unverified row": func(a *firewall.FirewallAction) {
			a.Before.Blocked[0].ActionID, a.Before.Blocked[0].Unverified = "earlier-action", true
			a.After.Blocked = without(a.After.Blocked, a.Before.Blocked[0].IP)
		},
		"member without its row":  func(a *firewall.FirewallAction) { a.After.Blocked = without(a.After.Blocked, "203.0.113.11") },
		"row of another action":   func(a *firewall.FirewallAction) { row(a, "member-two").ActionID = "member-three" },
		"row with another reason": func(a *firewall.FirewallAction) { row(a, "member-one").Reason = "other" },
		"row outlives its member": func(a *firewall.FirewallAction) {
			row(a, "member-one").ExpiresAt = row(a, "member-one").ExpiresAt.Add(time.Second)
		},
		"permanent member row": func(a *firewall.FirewallAction) { row(a, "member-one").ExpiresAt = time.Time{} },
		"member row starts after planning": func(a *firewall.FirewallAction) {
			r := row(a, "member-one")
			r.BlockedAt = a.CreatedAt.Add(time.Hour)
			r.ExpiresAt = r.BlockedAt.Add(time.Hour)
		},
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
		"target has an expired unverified alias": func(a *firewall.FirewallAction) {
			held := *row(a, "member-two")
			held.IP, held.ActionID = "::ffff:203.0.113.11", "earlier"
			held.BlockedAt, held.ExpiresAt = a.CreatedAt.Add(-time.Hour), a.CreatedAt
			held.Unverified = true
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
			if _, fresh, err := db.AdmitFirewallAction(in); fresh || !errors.Is(err, errInvalidFirewallManifest) {
				t.Fatalf("batch state change admitted or refused for another reason: fresh %v, %v", fresh, err)
			}
			if after := batchIndexImage(t, db); !bytes.Equal(after, image) {
				t.Fatal("refused batch changed journal or indexes")
			}
			if count, err := db.ReadFirewallScanBudget("2026-01-02T03"); err != nil || count != 0 {
				t.Fatalf("refused batch charged %d, %v", count, err)
			}
			in.Phase, in.UpdatedAt, in.AuditVersion = "planned", in.CreatedAt, 1
			raw, err := encodeFirewallActionRecord(in)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := decodeFirewallAction(raw); !errors.Is(err, firewall.ErrStateCorrupt) {
				t.Fatalf("invalid stored batch read as %v", err)
			}
		})
	}
	t.Run("drops an expired row", func(t *testing.T) {
		db := openSnapshotDB(t)
		in := batchFixture()
		in.After.Blocked = without(in.After.Blocked, "203.0.113.90")
		if a := admitFixture(t, db, in); !reflect.DeepEqual(a.After, in.After) {
			t.Fatalf("admitted After = %#v", a.After.Blocked)
		}
	})
}

func TestFirewallBatchStatesPreserveValidKeptRows(t *testing.T) {
	cases := map[string]func(*firewall.FirewallAction){
		"expired unverified row remains": func(a *firewall.FirewallAction) {
			a.Before.Blocked[0].ActionID, a.Before.Blocked[0].Unverified = "earlier-action", true
			a.After.Blocked[0] = a.Before.Blocked[0]
		},
		"later copy of expired row remains": func(a *firewall.FirewallAction) {
			expired := a.Before.Blocked[0]
			a.Before.Blocked = append(a.Before.Blocked, expired)
			a.After.Blocked = append(a.After.Blocked[1:], expired)
		},
		"member rows precede kept rows": func(a *firewall.FirewallAction) {
			a.After.Blocked = append(slices.Clone(a.After.Blocked[2:]), a.Before.Blocked...)
		},
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			in := batchFixture()
			change(&in)
			db := openSnapshotDB(t)
			admitFixture(t, db, in)
			got, err := db.ReadFirewallAction(in.Request.ID)
			if err != nil || !reflect.DeepEqual(got.Before, in.Before) || !reflect.DeepEqual(got.After, in.After) {
				t.Fatalf("stored states changed: before %#v, after %#v, error %v", got.Before, got.After, err)
			}
		})
	}
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
