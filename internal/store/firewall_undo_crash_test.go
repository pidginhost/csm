package store

import (
	"errors"
	"path/filepath"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/firewall"
)

// The original members must have real charges for preservation to be tested.
func chargedUndoBatch(t *testing.T, db *DB, k *observedKernel) firewall.FirewallAction {
	t.Helper()
	now := time.Now().UTC().Round(0)
	before := firewall.FirewallState{Blocked: []firewall.BlockedEntry{{IP: "192.0.2.1", Reason: "permanent", BlockedAt: now}}}
	if _, err := db.ReplaceFirewallState(0, before); err != nil {
		t.Fatal(err)
	}
	a := firewallBatchOf(t, db, "batch-live", 4, "member-1", "member-2")
	a.CreatedAt, a.After.Blocked = now, slices.Clone(before.Blocked)
	for i := range a.Members {
		a.Members[i].Budget.Window = now.Format("2006-01-02T15")
		a.After.Blocked = append(a.After.Blocked, batchMemberRow(a, a.Members[i]))
	}
	k.state = before
	result, err := lifecycleFor(t, db, func(firewall.FirewallAction) error { return nil }).Execute(a, k)
	if err != nil || result.Phase != "verified" {
		t.Fatalf("charged batch = %s, %v", result.Phase, err)
	}
	return result
}

// A member undo that dies at any lifecycle step recovers to one outcome
// after a restart: before its kernel write it fails and the member's row
// stays; after it the undo is verified and only that row is gone. The
// batch's other member and unrelated rows are untouched, nothing is
// charged, nothing stays pending, and a verified member cannot be undone
// twice (durable batch/undo).
func TestFirewallMemberUndoCrashAfterEachStep(t *testing.T) {
	for _, step := range []string{"admit", "executing", "observe", "apply", "applied", "verify", "verified", "audit", "ack"} {
		t.Run(step, func(t *testing.T) {
			db := openSnapshotDB(t)
			k := &observedKernel{}
			batch := chargedUndoBatch(t, db, k)
			window := batch.Members[0].Budget.Window
			budget, err := db.ReadFirewallScanBudget(window)
			if err != nil || budget != 2 {
				t.Fatalf("fixture charges = %d, %v; want 2", budget, err)
			}
			_, revision, err := db.ReadFirewallState()
			if err != nil {
				t.Fatal(err)
			}
			sentinel := errors.New("simulated process exit")
			after := func(at string) {
				if at == step {
					panic(sentinel)
				}
			}
			kk := &crashBatchKernel{after: after}
			kk.state = k.state
			crashed := false
			func() {
				defer func() {
					if caught := recover(); caught != nil {
						if caught != sentinel {
							panic(caught)
						}
						crashed = true
					}
				}()
				audit := func(firewall.FirewallAction) error { after("audit"); return nil }
				_, _ = (&firewall.Lifecycle{Store: &crashBatchStore{DB: db, after: after}, Audit: audit}).Undo(undoOf("undo-member-1", "member-1"), kk)
			}()
			if !crashed {
				t.Fatalf("did not reach crash checkpoint %s", step)
			}
			path := filepath.Dir(db.bolt.Path())
			if err = db.Close(); err != nil {
				t.Fatal(err)
			}
			reopened, err := Open(path)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = reopened.Close() })
			kk.after = func(string) {}
			recovery := &firewall.Lifecycle{Store: reopened, Audit: func(firewall.FirewallAction) error { return nil }}
			if err = recovery.Recover(kk); err != nil {
				t.Fatalf("restart recovery: %v", err)
			}
			got, err := reopened.ReadFirewallAction("undo-member-1")
			wantPhase := "verified"
			if step == "admit" || step == "executing" || step == "observe" {
				wantPhase = "failed"
			}
			if err != nil || got.Phase != wantPhase || got.AuditAck != got.AuditVersion || got.AuditVersion == 0 {
				t.Fatalf("undo outcome %q, %v; want %s", got.Phase, err, wantPhase)
			}
			wantState := copyFirewallStateForTest(batch.After)
			wantWrites := 0
			if wantPhase == "verified" {
				wantState.Blocked = withoutRow(wantState.Blocked, "203.0.113.20")
				wantWrites = 1
			}
			assertState := func() {
				t.Helper()
				state, rev, readErr := reopened.ReadFirewallState()
				if readErr != nil || rev != revision+1 || !reflect.DeepEqual(state, wantState) || !reflect.DeepEqual(kk.state, wantState) || kk.writes != wantWrites {
					t.Fatalf("member undo changed unrelated state or replayed: rows=%+v revision=%d writes=%d err=%v", state.Blocked, rev, kk.writes, readErr)
				}
			}
			assertState()
			if again, budgetErr := reopened.ReadFirewallScanBudget(window); budgetErr != nil || again != budget {
				t.Fatalf("undo charged: %d from %d, %v", again, budget, budgetErr)
			}
			if pending, pendErr := reopened.PendingFirewallActions(); pendErr != nil || len(pending) != 0 {
				t.Fatalf("pending after recovery %#v, %v", pending, pendErr)
			}
			if err = recovery.Recover(kk); err != nil {
				t.Fatalf("repeated recovery: %v", err)
			}
			var wantReplayErr error
			if wantPhase == "failed" {
				wantReplayErr = firewall.ErrActionFailed
			}
			again, replayErr := recovery.Undo(undoOf("undo-member-1", "member-1"), kk)
			if !errors.Is(replayErr, wantReplayErr) || again.Phase != wantPhase || again.AuditVersion != got.AuditVersion || again.AuditAck != got.AuditAck {
				t.Fatalf("same-ID undo changed outcome: %+v, %v", again, replayErr)
			}
			assertState()
			if wantPhase == "verified" {
				l := &firewall.Lifecycle{Store: reopened, Audit: func(firewall.FirewallAction) error { return nil }}
				if _, err = l.Undo(undoOf("undo-member-1-again", "member-1"), kk); !errors.Is(err, firewall.ErrStateConflict) {
					t.Fatalf("second undo of a verified member = %v", err)
				}
			}
			assertState()
			if again, budgetErr := reopened.ReadFirewallScanBudget(window); budgetErr != nil || again != 2 {
				t.Fatalf("replayed undo charged: %d, %v", again, budgetErr)
			}
			if pending, pendErr := reopened.PendingFirewallActions(); pendErr != nil || len(pending) != 0 {
				t.Fatalf("replayed undo left pending actions: %+v, %v", pending, pendErr)
			}
		})
	}
}
