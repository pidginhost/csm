package store

import (
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/firewall"
)

// victimFixture is a single-target block that removes the soonest-expiring
// temporary row to make room, as the durable single-target path plans it.
func victimFixture() firewall.FirewallAction {
	at := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	victim := firewall.BlockedEntry{IP: "203.0.113.90", Reason: "earlier", Source: "scan", BlockedAt: at.Add(-time.Hour), ExpiresAt: at.Add(30 * time.Minute)}
	kept := firewall.BlockedEntry{IP: "192.0.2.1", Reason: "permanent", BlockedAt: at.Add(-2 * time.Hour)}
	req := firewall.ActionRequest{ID: "evicting-block", Operation: "block", Target: "203.0.113.10", Reason: "brute force", Actor: "auto", Source: "scan", Automatic: true, TTL: time.Hour}
	budget := &firewall.ScanAdmission{Window: "2026-01-02T03", Limit: 4}
	row := firewall.BlockedEntry{IP: req.Target, Reason: req.Reason, Source: "unknown", BlockedAt: at, ExpiresAt: at.Add(req.TTL)}
	return firewall.FirewallAction{
		Request:   req,
		Budget:    budget,
		Members:   []firewall.ActionMember{{Request: req, Budget: budget, Victims: []firewall.BlockedEntry{victim}}},
		Before:    firewall.FirewallState{Blocked: []firewall.BlockedEntry{victim, kept}},
		After:     firewall.FirewallState{Blocked: []firewall.BlockedEntry{kept, row}},
		Revision:  1,
		CreatedAt: at,
	}
}

// A recorded victim is the row the action removed: undo restores it from
// this record, so it must be exactly the one row that named its address
// before the action, and no row may name that address after it.
func TestFirewallVictimsAreRowsTheActionRemoves(t *testing.T) {
	t.Run("recorded victim", func(t *testing.T) {
		db := openSnapshotDB(t)
		in := victimFixture()
		a := admitFixture(t, db, in)
		if len(a.Members) != 1 || !reflect.DeepEqual(a.Members[0].Victims, in.Members[0].Victims) {
			t.Fatalf("stored victims = %#v", a.Members)
		}
	})
	t.Run("victim expires during planning", func(t *testing.T) {
		db := openSnapshotDB(t)
		in := victimFixture()
		in.Before.Blocked[0].ExpiresAt = in.CreatedAt
		in.Members[0].Victims[0].ExpiresAt = in.CreatedAt
		a := admitFixture(t, db, in)
		if !a.Members[0].Victims[0].ExpiresAt.Equal(in.CreatedAt) {
			t.Fatal("victim expiry was renewed")
		}
	})
	alias := func(a *firewall.FirewallAction) firewall.BlockedEntry {
		row := a.Before.Blocked[0]
		row.IP = "::ffff:203.0.113.90"
		return row
	}
	cases := map[string]func(*firewall.FirewallAction){
		"unverified victim": func(a *firewall.FirewallAction) {
			a.Before.Blocked[0].Unverified = true
			a.Members[0].Victims[0].Unverified = true
		},
		"permanent victim": func(a *firewall.FirewallAction) {
			a.Before.Blocked[0].ExpiresAt = time.Time{}
			a.Members[0].Victims[0].ExpiresAt = time.Time{}
		},
		"victim never held":           func(a *firewall.FirewallAction) { a.Members[0].Victims[0].IP = "203.0.113.91" },
		"victim differs from its row": func(a *firewall.FirewallAction) { a.Members[0].Victims[0].Reason = "other" },
		"victim kept":                 func(a *firewall.FirewallAction) { a.After.Blocked = append(a.After.Blocked, a.Before.Blocked[0]) },
		"victim kept under another spelling": func(a *firewall.FirewallAction) {
			a.After.Blocked = append(a.After.Blocked, alias(a))
		},
		"victim address held twice": func(a *firewall.FirewallAction) {
			other := alias(a)
			other.Reason = "alias"
			a.Before.Blocked = append(a.Before.Blocked, other)
		},
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			db := openSnapshotDB(t)
			in := victimFixture()
			change(&in)
			if _, err := db.ReplaceFirewallState(0, in.Before); err != nil {
				t.Fatal(err)
			}
			if _, fresh, err := db.AdmitFirewallAction(in); fresh || !errors.Is(err, errInvalidFirewallManifest) {
				t.Fatalf("victim admitted or refused for another reason: fresh %v, %v", fresh, err)
			}
			if _, err := db.ReadFirewallAction(in.Request.ID); !errors.Is(err, ErrFirewallActionMissing) {
				t.Fatalf("refused victim left a record: %v", err)
			}
			in.Phase, in.UpdatedAt, in.AuditVersion = "planned", in.CreatedAt, 1
			raw, err := encodeFirewallActionRecord(in)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := decodeFirewallAction(raw); !errors.Is(err, firewall.ErrStateCorrupt) {
				t.Fatalf("invalid stored victim read as %v", err)
			}
		})
	}
}
