package store

import (
	"errors"
	"fmt"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/firewall"
	bolt "go.etcd.io/bbolt"
)

// liveBatch runs a verified batch of two automatic temporary blocks planned
// now, over committed state holding one unrelated permanent block and any
// extra rows given.
func liveBatch(t *testing.T, db *DB, l lifecycleRunner, k *observedKernel, extra ...firewall.BlockedEntry) firewall.FirewallAction {
	t.Helper()
	now := time.Now().UTC().Round(0)
	before := firewall.FirewallState{Blocked: append([]firewall.BlockedEntry{{IP: "192.0.2.1", Reason: "permanent", BlockedAt: now.Add(-time.Hour)}}, extra...)}
	if _, err := db.ReplaceFirewallState(0, before); err != nil {
		t.Fatal(err)
	}
	a := firewall.FirewallAction{
		Request: firewall.ActionRequest{ID: "batch-live", Operation: "block", Actor: "auto", Source: "scan", Automatic: true},
		Before:  before, After: copyFirewallStateForTest(before), Revision: 1, CreatedAt: now,
	}
	for i, id := range []string{"member-1", "member-2"} {
		m := firewall.ActionMember{Request: firewall.ActionRequest{ID: id, Operation: "block", Target: fmt.Sprintf("203.0.113.%d", 20+i), Reason: "brute force", Actor: "auto", Source: "scan", Automatic: true, TTL: time.Hour}}
		a.Members = append(a.Members, m)
		a.After.Blocked = append(a.After.Blocked, batchMemberRow(a, m))
	}
	k.state = before
	result, err := l.Execute(a, k)
	if err != nil || result.Phase != "verified" {
		t.Fatalf("batch = %s, %v", result.Phase, err)
	}
	return result
}

// runLater commits one more operator action that changes committed state
// after the batch.
func runLater(t *testing.T, db *DB, l lifecycleRunner, k *observedKernel, id string, change func(*firewall.FirewallState)) firewall.FirewallAction {
	t.Helper()
	state, revision, err := db.ReadFirewallState()
	if err != nil {
		t.Fatal(err)
	}
	after := copyFirewallStateForTest(state)
	change(&after)
	a := firewall.FirewallAction{Request: firewall.ActionRequest{ID: id, Operation: "block", Target: "198.51.100.40", Actor: "cli", Source: "cli"}, Before: state, After: after, Revision: revision, CreatedAt: time.Now().UTC().Round(0)}
	result, err := l.Execute(a, k)
	if err != nil || result.Phase != "verified" {
		t.Fatalf("%s = %s, %v", id, result.Phase, err)
	}
	return result
}

func undoOf(id, of string) firewall.ActionRequest {
	return firewall.ActionRequest{ID: id, Operation: "undo", Actor: "cli", Source: "cli", UndoOf: of}
}

func withoutRow(rows []firewall.BlockedEntry, ip string) []firewall.BlockedEntry {
	return slices.DeleteFunc(slices.Clone(rows), func(r firewall.BlockedEntry) bool { return r.IP == ip })
}

// A member-only undo removes that member's row against current state: later
// changes and the batch's other members stay, and the whole batch can no
// longer be undone because its complete after-state is gone.
func TestFirewallMemberUndoRemovesOnlyThatMember(t *testing.T) {
	db := openSnapshotDB(t)
	l := lifecycleFor(t, db, func(firewall.FirewallAction) error { return nil })
	k := &observedKernel{}
	batch := liveBatch(t, db, l, k)
	later := runLater(t, db, l, k, "later", func(s *firewall.FirewallState) {
		s.Blocked = append(s.Blocked, firewall.BlockedEntry{IP: "198.51.100.40", Reason: "operator", BlockedAt: batch.CreatedAt})
	})
	undo := undoOf("undo-member-1", "member-1")
	result, err := l.Undo(undo, k)
	if err != nil || result.Phase != "verified" || result.Request != undo {
		t.Fatalf("member undo = %#v, %v", result.Request, err)
	}
	state, _, err := db.ReadFirewallState()
	if err != nil || !reflect.DeepEqual(state.Blocked, withoutRow(later.After.Blocked, "203.0.113.20")) {
		t.Fatalf("state after member undo = %#v, %v", state.Blocked, err)
	}
	if again, err := l.Undo(undo, k); err != nil || again.Request != undo || again.Phase != "verified" {
		t.Fatalf("retried member undo = %#v, %v", again.Request, err)
	}
	if _, err := l.Undo(undoOf("undo-member-1-again", "member-1"), k); !errors.Is(err, firewall.ErrStateConflict) {
		t.Fatalf("second undo of one member = %v", err)
	}
	if _, err := l.Undo(undoOf("undo-batch", batch.Request.ID), k); !errors.Is(err, firewall.ErrStateConflict) {
		t.Fatalf("batch undo after a member undo = %v", err)
	}
	if got, _, _ := db.ReadFirewallState(); !reflect.DeepEqual(got, state) {
		t.Fatalf("refused undo changed state: %#v", got.Blocked)
	}
}

// A member whose row changed after the batch, or whose address another row
// now also names, is not the block the batch wrote: its undo refuses.
func TestFirewallMemberUndoRefusesChangedRows(t *testing.T) {
	for name, change := range map[string]func(*firewall.FirewallState){
		"row replaced": func(s *firewall.FirewallState) {
			s.Blocked = append(withoutRow(s.Blocked, "203.0.113.20"), firewall.BlockedEntry{IP: "203.0.113.20", Reason: "operator", BlockedAt: time.Now().UTC().Round(0)})
		},
		"row removed": func(s *firewall.FirewallState) { s.Blocked = withoutRow(s.Blocked, "203.0.113.20") },
		"address aliased": func(s *firewall.FirewallState) {
			s.Blocked = append(s.Blocked, firewall.BlockedEntry{IP: "::ffff:203.0.113.20", Reason: "operator", BlockedAt: time.Now().UTC().Round(0)})
		},
		// Expiry cannot settle an unverified row; its owner must.
		"expired unverified row on the address": func(s *firewall.FirewallState) {
			now := time.Now().UTC().Round(0)
			s.Blocked = append(s.Blocked, firewall.BlockedEntry{IP: "::ffff:203.0.113.20", Reason: "unproven", BlockedAt: now.Add(-2 * time.Hour), ExpiresAt: now.Add(-time.Hour), ActionID: "earlier-attempt", Unverified: true})
		},
	} {
		t.Run(name, func(t *testing.T) {
			db := openSnapshotDB(t)
			l := lifecycleFor(t, db, func(firewall.FirewallAction) error { return nil })
			k := &observedKernel{}
			liveBatch(t, db, l, k)
			runLater(t, db, l, k, "later", change)
			state, revision, err := db.ReadFirewallState()
			if err != nil {
				t.Fatal(err)
			}
			if _, err := l.Undo(undoOf("undo-member-1", "member-1"), k); !errors.Is(err, firewall.ErrStateConflict) {
				t.Fatalf("undo of a changed member = %v", err)
			}
			if got, rev, _ := db.ReadFirewallState(); rev != revision || !reflect.DeepEqual(got, state) {
				t.Fatalf("refused undo changed state at revision %d: %#v", rev, got.Blocked)
			}
			if _, err := db.ReadFirewallAction("undo-member-1"); !errors.Is(err, ErrFirewallActionMissing) {
				t.Fatalf("refused undo left a record: %v", err)
			}
		})
	}
}

// Only a verified member of a stored batch can be undone on its own.
func TestFirewallMemberUndoNeedsAVerifiedMember(t *testing.T) {
	db := openSnapshotDB(t)
	l := lifecycleFor(t, db, func(firewall.FirewallAction) error { return nil })
	k := &observedKernel{}
	liveBatch(t, db, l, k)
	if _, err := l.Undo(undoOf("undo-nothing", "no-such-member"), k); !errors.Is(err, firewall.ErrActionMissing) {
		t.Fatalf("undo of an unknown ID = %v", err)
	}

	db = openSnapshotDB(t)
	l = lifecycleFor(t, db, func(firewall.FirewallAction) error { return nil })
	k = &observedKernel{}
	now := time.Now().UTC().Round(0)
	before := firewall.FirewallState{Blocked: []firewall.BlockedEntry{{IP: "192.0.2.1", Reason: "permanent", BlockedAt: now.Add(-time.Hour)}}}
	k.afterWrite = func() { k.state = before }
	if _, err := db.ReplaceFirewallState(0, before); err != nil {
		t.Fatal(err)
	}
	a := firewall.FirewallAction{Request: firewall.ActionRequest{ID: "batch-failed", Operation: "block", Actor: "auto", Source: "scan", Automatic: true}, Before: before, After: copyFirewallStateForTest(before), Revision: 1, CreatedAt: now}
	for i, id := range []string{"member-1", "member-2"} {
		m := firewall.ActionMember{Request: firewall.ActionRequest{ID: id, Operation: "block", Target: fmt.Sprintf("203.0.113.%d", 20+i), Reason: "brute force", Actor: "auto", Source: "scan", Automatic: true, TTL: time.Hour}}
		a.Members = append(a.Members, m)
		a.After.Blocked = append(a.After.Blocked, batchMemberRow(a, m))
	}
	k.state = before
	if result, err := l.Execute(a, k); !errors.Is(err, firewall.ErrActionFailed) || result.Phase != "failed" {
		t.Fatalf("batch = %s, %v; want a proven failure", result.Phase, err)
	}
	if _, err := l.Undo(undoOf("undo-failed-member", "member-1"), k); err == nil || errors.Is(err, firewall.ErrStateConflict) {
		t.Fatalf("undo of a failed batch's member = %v, want a refusal that names the outcome", err)
	}
	if _, err := db.ReadFirewallAction("undo-failed-member"); !errors.Is(err, ErrFirewallActionMissing) {
		t.Fatalf("refused undo left a record: %v", err)
	}
}

// Undo restores rows that are still live with their original expiry, and
// never puts a row that has expired since back into committed state.
func TestFirewallUndoNeverRestoresExpiredRows(t *testing.T) {
	db := openSnapshotDB(t)
	l := lifecycleFor(t, db, func(firewall.FirewallAction) error { return nil })
	now := time.Now().UTC().Round(0)
	live := firewall.BlockedEntry{IP: "203.0.113.30", Reason: "live", Source: "scan", BlockedAt: now.Add(-time.Hour), ExpiresAt: now.Add(time.Hour)}
	expired := firewall.BlockedEntry{IP: "203.0.113.31", Reason: "expired", Source: "scan", BlockedAt: now.Add(-2 * time.Hour), ExpiresAt: now.Add(-time.Hour)}
	// An operator undo cannot resurrect an expired unverified row.
	unverified := firewall.BlockedEntry{IP: "203.0.113.32", Reason: "unproven", Source: "scan", BlockedAt: now.Add(-2 * time.Hour), ExpiresAt: now.Add(-time.Hour), ActionID: "earlier-attempt", Unverified: true}
	permanent := firewall.BlockedEntry{IP: "192.0.2.1", Reason: "permanent", BlockedAt: now.Add(-time.Hour)}
	before := firewall.FirewallState{
		Blocked:    []firewall.BlockedEntry{live, expired, unverified, permanent},
		Allowed:    []firewall.AllowedEntry{{IP: "198.51.100.5", Reason: "temporary", Source: "manual", ExpiresAt: now.Add(-time.Minute)}},
		BlockedNet: []firewall.SubnetEntry{{CIDR: "198.51.100.0/28", Reason: "subnet", Source: "manual", BlockedAt: now.Add(-2 * time.Hour), ExpiresAt: now.Add(-time.Hour)}},
	}
	if _, err := db.ReplaceFirewallState(0, before); err != nil {
		t.Fatal(err)
	}
	k := &observedKernel{state: before}
	flush := firewall.FirewallAction{Request: firewall.ActionRequest{ID: "flush-all", Operation: "flush", Target: "*", Actor: "cli", Source: "cli"}, Before: before, Revision: 1, CreatedAt: now}
	if result, err := l.Execute(flush, k); err != nil || result.Phase != "verified" {
		t.Fatalf("flush = %s, %v", result.Phase, err)
	}
	result, err := l.Undo(undoOf("undo-flush", "flush-all"), k)
	if err != nil || result.Phase != "verified" {
		t.Fatalf("undo = %s, %v", result.Phase, err)
	}
	state, _, err := db.ReadFirewallState()
	if err != nil || !reflect.DeepEqual(state.Blocked, []firewall.BlockedEntry{live, permanent}) || len(state.Allowed) != 0 || len(state.BlockedNet) != 0 {
		t.Fatalf("undo restored %#v, %v", state, err)
	}
}

// A batch may keep an expired row on a member's address; undoing that
// member removes both, since the expired row blocks nothing.
func TestFirewallMemberUndoDropsExpiredRowsOnItsAddress(t *testing.T) {
	db := openSnapshotDB(t)
	l := lifecycleFor(t, db, func(firewall.FirewallAction) error { return nil })
	k := &observedKernel{}
	now := time.Now().UTC().Round(0)
	earlier := firewall.BlockedEntry{IP: "203.0.113.20", Reason: "earlier", Source: "scan", BlockedAt: now.Add(-2 * time.Hour), ExpiresAt: now.Add(-time.Hour)}
	batch := liveBatch(t, db, l, k, earlier)
	if _, err := l.Undo(undoOf("undo-member-1", "member-1"), k); err != nil {
		t.Fatalf("undo of a member beside an expired row = %v", err)
	}
	state, _, err := db.ReadFirewallState()
	want := withoutRow(batch.After.Blocked, "203.0.113.20")
	if err != nil || !reflect.DeepEqual(state.Blocked, want) {
		t.Fatalf("state = %#v, %v; want %#v", state.Blocked, err, want)
	}
}

// A member ID leads to the one batch that indexes it; an index entry that
// names a batch without that member is damage, not a lookup miss.
func TestFirewallBatchMemberLookup(t *testing.T) {
	db := openSnapshotDB(t)
	l := lifecycleFor(t, db, func(firewall.FirewallAction) error { return nil })
	batch := liveBatch(t, db, l, &observedKernel{})
	if got, err := db.ReadFirewallBatchMember("member-2"); err != nil || !got.SameManifest(batch) {
		t.Fatalf("member lookup = %#v, %v", got.Request, err)
	}
	for _, id := range []string{"batch-live", "no-such-member"} {
		if _, err := db.ReadFirewallBatchMember(id); !errors.Is(err, ErrFirewallActionMissing) {
			t.Fatalf("lookup of %s = %v", id, err)
		}
	}
	for _, entry := range []firewallMemberIndexEntry{{Batch: "no-such-batch"}, {Batch: "batch-live"}} {
		if err := db.bolt.Update(func(tx *bolt.Tx) error {
			raw, err := encodeFirewallJournal(entry)
			if err != nil {
				return err
			}
			return tx.Bucket([]byte(firewallMemberIndexBucket)).Put([]byte("stray-member"), raw)
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := db.ReadFirewallBatchMember("stray-member"); !errors.Is(err, firewall.ErrStateCorrupt) {
			t.Fatalf("lookup through an entry naming %s = %v", entry.Batch, err)
		}
	}
}
