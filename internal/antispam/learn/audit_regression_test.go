package learn

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/store"
)

func TestAuditResumesCoverageAcrossLargerBatch(t *testing.T) {
	f := newAuditFixture(t)
	for i, d := range []byte("abc") {
		f.add(t, uint64(i+1), digest(d), 2, t0, 1001+i)
	}
	if prog, err := f.publisher().AuditTurn(context.Background(), 1, t0); err != nil || prog.Checked != 1 {
		t.Fatalf("initial audit: %+v, %v", prog, err)
	}
	p := f.publisher()
	if prog, err := p.AuditTurn(context.Background(), AuditBatch, t0); err != nil || prog.Checked != 2 || !prog.RotationDone {
		t.Fatalf("resumed audit: %+v, %v", prog, err)
	}
	if p.FreshMatchingAllowed() {
		t.Fatal("matching resumed before checking the start of the rotation")
	}
	if prog, err := p.AuditTurn(context.Background(), AuditBatch, t0); err != nil || prog.Checked != 3 {
		t.Fatalf("wrapped audit: %+v, %v", prog, err)
	}
	if !p.FreshMatchingAllowed() {
		t.Fatal("matching stayed blocked after every target was checked")
	}
}

func TestAuditDistinguishesPendingPublicationFromLoss(t *testing.T) {
	for _, tc := range []struct {
		name                              string
		phase                             Phase
		committed, reset, restoring, lost bool
	}{
		{name: "existing-read", phase: PhaseRead, committed: true, lost: true},
		{name: "existing-add", phase: PhaseAddSent, committed: true, lost: true},
		{name: "first-read", phase: PhaseRead},
		{name: "first-add", phase: PhaseAddSent},
		{name: "reset-read", phase: PhaseRead, committed: true, reset: true},
		{name: "delete-pending", phase: PhaseDeletePending, committed: true},
		{name: "delete-sent", phase: PhaseDeleteSent, committed: true},
		{name: "add-pending", phase: PhaseAddPending, committed: true},
		{name: "reset-add-sent", phase: PhaseAddSent, committed: true, restoring: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newAuditFixture(t)
			f.add(t, 1, digest('a'), 2, t0, 1001)
			p := f.publisher()
			rotation(t, p, AuditBatch, t0)
			if err := f.ledger.Update(func(tx LedgerTx) error {
				c, _, err := tx.Cluster(1)
				if err != nil {
					return err
				}
				if !tc.committed {
					c.UIDs = nil
				}
				if err = tx.PutCluster(c); err != nil {
					return err
				}
				target, _, err := tx.Target(c.Anchor)
				if err != nil {
					return err
				}
				target.Phase, target.ResetPending = tc.phase, tc.reset
				if tc.restoring {
					target.RestoreT = target.T
				}
				return tx.PutTarget(target)
			}); err != nil {
				t.Fatal(err)
			}
			f.storage.mu.Lock()
			delete(f.storage.values, digest('a'))
			f.storage.mu.Unlock()
			if _, err := p.AuditTurn(context.Background(), AuditBatch, t0); err != nil {
				t.Fatal(err)
			}
			if p.RebuildNeeded() != tc.lost || tc.lost && p.FreshMatchingAllowed() {
				t.Fatalf("rebuilding %v, fresh matching %v, want loss %v", p.RebuildNeeded(), p.FreshMatchingAllowed(), tc.lost)
			}
		})
	}
}

type failAuditUpdate struct {
	kv
	at, calls int
}

func (db *failAuditUpdate) LearnUpdate(fn func(store.LearnTx) error) error {
	db.calls++
	return db.kv.LearnUpdate(func(tx store.LearnTx) error {
		if err := fn(tx); err != nil {
			return err
		}
		if db.calls == db.at {
			return errors.New("injected commit failure")
		}
		return nil
	})
}

func TestAuditLossClosesGateDespiteCommitFailure(t *testing.T) {
	for _, failAt := range []int{1, 2, 3} {
		t.Run(fmt.Sprint(failAt), func(t *testing.T) {
			f := newAuditFixture(t)
			f.add(t, 1, digest('a'), 2, t0, 1001)
			f.add(t, 2, digest('b'), 2, t0, 1002)
			p := f.publisher()
			rotation(t, p, AuditBatch, t0)
			if !p.FreshMatchingAllowed() {
				t.Fatal("initial audit did not open gate")
			}
			f.storage.mu.Lock()
			delete(f.storage.values, digest('a'))
			f.storage.values[digest('b')] = 4
			f.storage.mu.Unlock()
			base := f.ledger.db
			f.ledger.db = &failAuditUpdate{kv: base, at: failAt}
			_, err := p.AuditTurn(context.Background(), AuditBatch, t0)
			if !errors.Is(err, ErrStateIO) {
				t.Fatalf("audit error = %v", err)
			}
			if p.FreshMatchingAllowed() || !p.RebuildNeeded() {
				t.Error("observed loss was forgotten when recording repair failed")
			}
			f.ledger.db = base
			rotation(t, p, AuditBatch, t0)
			if !p.FreshMatchingAllowed() || p.RebuildNeeded() {
				t.Fatal("gate did not recover after successful audit and repair")
			}
		})
	}
}

func TestRepairTurnBoundsInvalidBatch(t *testing.T) {
	for _, limit := range []int{0, -1, MaxExplicitDigests + 1} {
		t.Run(fmt.Sprint(limit), func(t *testing.T) {
			f := newAuditFixture(t)
			if err := f.ledger.Update(func(tx LedgerTx) error {
				for i := 1; i <= AuditBatch+1; i++ {
					if err := tx.PutTarget(Target{Digest: Digest(fmt.Sprintf("%0128x", i)), Phase: PhaseRead}); err != nil {
						return err
					}
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			defer func() {
				if v := recover(); v != nil {
					t.Errorf("repair panicked for limit %d: %v", limit, v)
				}
			}()
			if n, err := f.publisher().RepairTurn(context.Background(), limit); err != nil || n != AuditBatch {
				t.Fatalf("repair turned %d targets, error %v", n, err)
			}
		})
	}
}

func TestRepairTurnSettlesCompletedCoverage(t *testing.T) {
	f := newAuditFixture(t)
	f.add(t, 1, digest('a'), 2, t0, 1001)
	f.storage.mu.Lock()
	delete(f.storage.values, digest('a'))
	f.storage.mu.Unlock()
	p := f.publisher()
	if _, err := p.AuditTurn(context.Background(), AuditBatch, t0); err != nil {
		t.Fatal(err)
	}
	if p.FreshMatchingAllowed() || !p.RebuildNeeded() {
		t.Fatal("matching was not blocked before repair")
	}
	if n, err := p.RepairTurn(context.Background(), 1); err != nil || n != 1 {
		t.Fatalf("repair turned %d targets, error %v", n, err)
	}
	if !p.FreshMatchingAllowed() || p.RebuildNeeded() {
		t.Fatal("matching remained blocked after the last repair")
	}
}

func TestRepairRetiresExpiredAnchorsBeforeReconstruction(t *testing.T) {
	f := newAuditFixture(t)
	f.add(t, 1, digest('a'), 2, t0.Add(-Retention), 1001)
	f.add(t, 2, digest('b'), 4, t0, 1002, 1003)
	f.storage.mu.Lock()
	f.storage.values = map[Digest]int64{}
	f.storage.mu.Unlock()
	p := f.publisher()
	p.now = func() time.Time { return t0 }
	if _, err := p.AuditTurn(context.Background(), AuditBatch, t0); err != nil {
		t.Fatal(err)
	}
	if _, err := p.RepairTurn(context.Background(), AuditBatch); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.storage.value(digest('a')); ok {
		t.Error("expired anchor was reconstructed")
	}
	if v, ok := f.storage.value(digest('b')); !ok || v != 4 {
		t.Errorf("live anchor = %d, present %v", v, ok)
	}
	if target, ok := f.targetOf(t, digest('a')); !ok || target.T != 0 || target.Revision != 2 {
		t.Errorf("expired target = %+v, present %v", target, ok)
	}
	if adds, deletes := f.storage.counts(); !reflect.DeepEqual(adds, []int32{4}) || deletes != 0 {
		t.Errorf("rebuild sent adds %v, deletes %d", adds, deletes)
	}
}

func TestRetirementCountsOnlyOpenAdmissions(t *testing.T) {
	for _, tc := range []struct {
		name                          string
		kind                          IntentKind
		done, clusterDone, keepsAlive bool
	}{
		{name: "report", kind: IntentReport, keepsAlive: true},
		{name: "operator", kind: IntentOperator, keepsAlive: true},
		{name: "forget", kind: IntentForget},
		{name: "retire", kind: IntentRetire},
		{name: "cancelled", kind: IntentReport, done: true},
		{name: "cancelled-cluster", kind: IntentReport, clusterDone: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newAuditFixture(t)
			f.add(t, 1, digest('a'), 2, t0, 1001)
			if err := f.ledger.Update(func(tx LedgerTx) error {
				return tx.PutIntent(Intent{ID: "pending", Kind: tc.kind, Admitted: t0.Add(day), Done: tc.done,
					Clusters: []IntentCluster{{ClusterID: 1, Revision: 1, Done: tc.clusterDone}}})
			}); err != nil {
				t.Fatal(err)
			}
			ids, err := f.publisher().RetireDue(t0.Add(Retention))
			if err != nil || (len(ids) == 0) != tc.keepsAlive {
				t.Fatalf("retired %v, keepsAlive %v, error %v", ids, tc.keepsAlive, err)
			}
		})
	}
}

func TestRetirementKeepsGuardCharge(t *testing.T) {
	for _, operator := range []bool{false, true} {
		t.Run(fmt.Sprint(operator), func(t *testing.T) {
			f := newAuditFixture(t)
			f.add(t, 1, digest('a'), 4, t0, 1001, 1002)
			if err := f.ledger.Update(func(tx LedgerTx) error {
				c, _, err := tx.Cluster(1)
				if err != nil {
					return err
				}
				if operator {
					if err := tx.AddUsage(1001, false, Usage{BodyBytes: -c.BodyLen, Aliases: -1}); err != nil {
						return err
					}
					if err := tx.AddUsage(0, true, c.Charges[0].Usage); err != nil {
						return err
					}
					c.Operator, c.Charges[0].Operator = true, true
				}
				c.Aliases = append(c.Aliases, digest('b'), digest('c'))
				c.Charges = append(c.Charges, Charge{UID: 1002, Usage: Usage{Aliases: 2}})
				for _, d := range []Digest{digest('b'), digest('c')} {
					if err := tx.PutAlias(d, c.ID); err != nil {
						return err
					}
				}
				if err := tx.AddUsage(1002, false, Usage{Aliases: 2}); err != nil {
					return err
				}
				return tx.PutCluster(c)
			}); err != nil {
				t.Fatal(err)
			}
			p := f.publisher()
			if ids, err := p.RetireDue(t0.Add(Retention)); err != nil || !reflect.DeepEqual(ids, []uint64{1}) {
				t.Fatalf("retired %v, error %v", ids, err)
			}
			if err := f.ledger.View(func(v LedgerView) error {
				u, err := v.Usage(1001, operator)
				if err != nil {
					return err
				}
				if u != (Usage{Aliases: 1}) {
					t.Errorf("guard allowance refunded: %+v", u)
				}
				u, err = v.Usage(1002, false)
				if err != nil {
					return err
				}
				if u != (Usage{}) {
					t.Errorf("removed aliases still charged: %+v", u)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			if _, err := p.RetireDue(t0.Add(Retention + day)); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestRetirementCleanupSurvivesUnlinkFailure(t *testing.T) {
	f := newAuditFixture(t)
	f.add(t, 1, digest('a'), 2, t0, 1001)
	bodyPath := filepath.Join(f.bodies.Dir, BodyName(1))
	if err := os.Remove(bodyPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(bodyPath, 0o700); err != nil {
		t.Fatal(err)
	}
	blocker := filepath.Join(bodyPath, "blocker")
	if err := os.WriteFile(blocker, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	p := f.publisher()
	if ids, err := p.RetireDue(t0.Add(Retention)); err == nil || !reflect.DeepEqual(ids, []uint64{1}) {
		t.Fatalf("retired %v, error %v", ids, err)
	}
	if err := f.ledger.View(func(v LedgerView) error {
		c, ok, err := v.Cluster(1)
		if err != nil {
			return err
		}
		if !ok || !c.Retired || c.Revision != 2 {
			t.Errorf("cleanup reference: %+v, present %v", c, ok)
		}
		_, alias, aliasErr := v.Alias(digest('a'))
		if aliasErr != nil {
			return aliasErr
		} else if alias {
			t.Error("alias survived durable zero target")
		}
		u, err := v.Usage(1001, false)
		if u.BodyBytes == 0 || u.Aliases != 1 {
			t.Errorf("credited before unlink: %+v", u)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if target, ok := f.targetOf(t, digest('a')); !ok || target.T != 0 || target.Revision != 2 {
		t.Fatalf("zero target: %+v, present %v", target, ok)
	}
	if n, err := p.RepairTurn(context.Background(), AuditBatch); err == nil || n != 1 {
		t.Fatalf("zero-target repair during cleanup failure: %d, %v", n, err)
	}
	if _, ok := f.storage.value(digest('a')); ok {
		t.Error("body cleanup failure blocked deletion of the expired anchor")
	}
	// The operator clears the obstruction. Body removal never deletes a
	// directory, so the whole thing goes.
	if err := os.RemoveAll(bodyPath); err != nil {
		t.Fatal(err)
	}
	// Restart and retry under a backward clock: existing cleanup still runs.
	if ids, err := f.publisher().RetireDue(t0); err != nil || len(ids) != 0 {
		t.Fatalf("cleanup retry: %v, %v", ids, err)
	}
	if _, err := os.Stat(bodyPath); !os.IsNotExist(err) {
		t.Fatalf("body not removed: %v", err)
	}
	if err := f.ledger.View(func(v LedgerView) error {
		_, ok, err := v.Cluster(1)
		if ok {
			t.Error("cleanup reference survived successful unlink")
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

// RetireDue uses its supplied clock for both retention and target metadata.
func TestRetirementUsesTurnTime(t *testing.T) {
	f := newAuditFixture(t)
	f.add(t, 1, digest('a'), 2, t0, 1001)
	now := t0.Add(Retention)
	p := f.publisher()
	p.now = func() time.Time { return now.Add(-time.Hour) }
	if _, err := p.RetireDue(now); err != nil {
		t.Fatal(err)
	}
	if target, _ := f.targetOf(t, digest('a')); !target.Updated.Equal(now) {
		t.Fatalf("target time %v, want %v", target.Updated, now)
	}
}

func TestRetirementCleanupCommitFailureRetriesOnce(t *testing.T) {
	f := newAuditFixture(t)
	f.add(t, 1, digest('a'), 2, t0.Add(-Retention), 1001)
	f.add(t, 2, digest('b'), 2, t0, 1001)
	var initial Usage
	if err := f.ledger.View(func(v LedgerView) error {
		var err error
		initial, err = v.Usage(1001, false)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	base := f.ledger.db
	f.ledger.db = &failAuditUpdate{kv: base, at: 2}
	if ids, err := f.publisher().RetireDue(t0); !errors.Is(err, ErrStateIO) || !reflect.DeepEqual(ids, []uint64{1}) {
		t.Fatalf("cleanup commit: retired %v, error %v", ids, err)
	}
	if _, err := os.Stat(filepath.Join(f.bodies.Dir, BodyName(1))); !os.IsNotExist(err) {
		t.Fatalf("body unlink did not precede cleanup commit: %v", err)
	}
	if err := f.ledger.View(func(v LedgerView) error {
		c, ok, err := v.Cluster(1)
		if err != nil {
			return err
		}
		if !ok || !c.Retired {
			t.Error("cleanup reference lost on rollback")
		}
		u, err := v.Usage(1001, false)
		if u != initial {
			t.Errorf("usage changed on rollback: %+v, want %+v", u, initial)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	f.ledger.db = base
	for range 2 {
		if _, err := f.publisher().RetireDue(t0); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.ledger.View(func(v LedgerView) error {
		c, ok, err := v.Cluster(2)
		if err != nil {
			return err
		}
		if !ok {
			t.Fatal("unexpired cluster was removed")
		}
		u, err := v.Usage(1001, false)
		if u != (Usage{BodyBytes: c.BodyLen, Aliases: 2}) {
			t.Errorf("cleanup credited more than once or lost guard charge: %+v", u)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	guard, ok := f.targetOf(t, digest('a'))
	want := &Charge{UID: 1001, Usage: Usage{Aliases: 1}}
	if !ok || guard.T != 0 || !reflect.DeepEqual(guard.GuardCharge, want) {
		t.Fatalf("guard lost its charge owner: %+v, present %v", guard, ok)
	}
}

func TestRepairCursorAdvancesPastFailingTarget(t *testing.T) {
	f := newAuditFixture(t)
	for i, d := range []byte("abc") {
		f.add(t, uint64(i+1), digest(d), 2, t0, 1001+i)
		f.storage.set(digest(d), 4)
	}
	p := f.publisher()
	p.now = func() time.Time { return t0 }
	if _, err := p.AuditTurn(context.Background(), AuditBatch, t0); err != nil {
		t.Fatal(err)
	}
	f.storage.onDelete = func(d Digest) (bool, error) {
		if d == digest('a') {
			return false, ErrRejected
		}
		return true, nil
	}
	if n, err := p.RepairTurn(context.Background(), 1); n != 1 || !errors.Is(err, ErrRejected) {
		t.Fatalf("failed repair: %d, %v", n, err)
	}
	p = f.publisher()
	p.now = func() time.Time { return t0 }
	for range 2 {
		if n, err := p.RepairTurn(context.Background(), 1); err != nil || n != 1 {
			t.Fatalf("resumed repair: %d, %v", n, err)
		}
	}
	for _, d := range []Digest{digest('b'), digest('c')} {
		if v, ok := f.storage.value(d); !ok || v != 2 {
			t.Errorf("later anchor %s stayed at %d, present %v", d[:1], v, ok)
		}
	}
	if v, ok := f.storage.value(digest('a')); !ok || v != 4 {
		t.Errorf("failed anchor changed: %d, present %v", v, ok)
	}
	if p.FreshMatchingAllowed() {
		t.Fatal("restart bypassed audit and repair coverage")
	}
}
