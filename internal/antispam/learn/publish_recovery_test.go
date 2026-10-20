package learn

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/pidginhost/csm/internal/store"
)

type publishFaultLedger struct {
	kv
	updateErr error
	viewErr   error
}

func (l *publishFaultLedger) LearnUpdate(fn func(store.LearnTx) error) error {
	return l.kv.LearnUpdate(func(tx store.LearnTx) error {
		if err := fn(tx); err != nil {
			return err
		}
		return l.updateErr
	})
}

func (l *publishFaultLedger) LearnView(fn func(store.LearnTx) error) error {
	if l.viewErr != nil {
		return l.viewErr
	}
	return l.kv.LearnView(fn)
}

func (f *publishFixture) reopen(t *testing.T) {
	t.Helper()
	db := f.ledger.db.(*store.DB)
	dir := filepath.Dir(db.Path())
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	f.ledger = Open(db)
}

func TestPublishResetResumesAfterDeleteAcrossTurns(t *testing.T) {
	for _, lateValue := range []int64{-1, 8, 10} {
		t.Run(fmt.Sprintf("late_value=%d", lateValue), func(t *testing.T) {
			f := newPublishFixture(t, 8)
			f.storage.set(f.anchor, 26)
			p := f.publisher()
			p.attempts = 1
			res, err := turn(t, p, f.anchor)
			if err != nil || res.Done || res.Uncertain || res.Phase != PhaseAddPending {
				t.Fatalf("res %+v err %v", res, err)
			}
			if adds, deletes := f.storage.counts(); len(adds) != 0 || deletes != 1 {
				t.Fatalf("first turn: adds %v deletes %d", adds, deletes)
			}
			if lateValue >= 0 {
				f.storage.set(f.anchor, lateValue)
			}
			f.reopen(t)
			if res, err = turn(t, f.publisher(), f.anchor); err != nil || !res.Done || res.Value != 8 {
				t.Fatalf("resume res %+v err %v", res, err)
			}
			wantDeletes := 1
			if lateValue >= 0 {
				wantDeletes++
			}
			if adds, deletes := f.storage.counts(); !reflect.DeepEqual(adds, []int32{8}) || deletes != wantDeletes {
				t.Fatalf("adds %v deletes %d; want [8], %d", adds, deletes, wantDeletes)
			}
		})
	}
}

func TestPublishReappearingDigestBeforeResetAddIsDeleted(t *testing.T) {
	f := newPublishFixture(t, 8)
	f.storage.set(f.anchor, 26)
	lateWrite := false
	f.storage.onRead = func() {
		if !lateWrite && f.target(t).Phase == PhaseAddPending {
			lateWrite = true
			f.storage.set(f.anchor, 8)
		}
	}
	f.storage.onAdd = func(Digest, int32) (bool, error) {
		if _, present := f.storage.value(f.anchor); present {
			t.Fatal("reset add sent without verified absence")
		}
		if got := f.target(t); got.Phase != PhaseAddSent || !got.ResetPending {
			t.Fatalf("reset add not journaled: %+v", got)
		}
		return true, nil
	}
	res, err := turn(t, f.publisher(), f.anchor)
	if err != nil || !res.Done || res.Value != 8 || !lateWrite {
		t.Fatalf("res %+v err %v late write %t", res, err, lateWrite)
	}
	if adds, deletes := f.storage.counts(); !reflect.DeepEqual(adds, []int32{8}) || deletes != 2 {
		t.Fatalf("adds %v deletes %d", adds, deletes)
	}
}

func TestPublishDeleteNeedsVerifiedAbsence(t *testing.T) {
	for _, refusal := range []error{nil, ErrUncertain, ErrRejected} {
		name := "acknowledged"
		if refusal != nil {
			name = refusal.Error()
		}
		t.Run(name, func(t *testing.T) {
			f := newPublishFixture(t, 8)
			f.storage.set(f.anchor, 26)
			f.storage.onDelete = func(Digest) (bool, error) { return false, refusal }
			res, err := turn(t, f.publisher(), f.anchor)
			if refusal == ErrRejected {
				if !errors.Is(err, ErrRejected) || res.Uncertain {
					t.Fatalf("res %+v err %v", res, err)
				}
			} else if err != nil || !res.Uncertain {
				t.Fatalf("res %+v err %v", res, err)
			}
			if res.Done {
				t.Fatalf("res %+v err %v", res, err)
			}
			if adds, deletes := f.storage.counts(); len(adds) != 0 || deletes != 1 {
				t.Fatalf("adds %v deletes %d", adds, deletes)
			}
			f.reopen(t)
			f.storage.onDelete = nil
			f.storage.readErr = ErrRejected
			if res, err = turn(t, f.publisher(), f.anchor); !errors.Is(err, ErrReadFailed) || res.Done {
				t.Fatalf("failed read: res %+v err %v", res, err)
			}
			if adds, deletes := f.storage.counts(); len(adds) != 0 || deletes != 1 {
				t.Fatalf("mutation after failed read: adds %v deletes %d", adds, deletes)
			}
			f.storage.readErr = nil
			if res, err = turn(t, f.publisher(), f.anchor); err != nil || !res.Done || res.Value != 8 {
				t.Fatalf("recovery res %+v err %v", res, err)
			}
			if adds, deletes := f.storage.counts(); !reflect.DeepEqual(adds, []int32{8}) || deletes != 2 {
				t.Fatalf("recovery adds %v deletes %d", adds, deletes)
			}
		})
	}
}

func TestPublishLostResetReplySurvivesReopen(t *testing.T) {
	for _, mutation := range []string{"delete", "add"} {
		for _, applied := range []bool{false, true} {
			name := mutation + "/not_applied"
			if applied {
				name = mutation + "/applied"
			}
			t.Run(name, func(t *testing.T) {
				f := newPublishFixture(t, 8)
				f.storage.set(f.anchor, 8)
				f.editTarget(t, func(cur *Target) { cur.ResetPending = true })
				wantPhase := PhaseDeleteSent
				if mutation == "delete" {
					f.storage.onDelete = func(Digest) (bool, error) { return applied, ErrUncertain }
				} else {
					wantPhase = PhaseAddSent
					f.storage.onAdd = func(Digest, int32) (bool, error) { return applied, ErrUncertain }
				}
				res, err := turn(t, f.publisher(), f.anchor)
				if err != nil || res.Done || !res.Uncertain || res.Phase != wantPhase || !f.target(t).ResetPending {
					t.Fatalf("res %+v err %v target %+v", res, err, f.target(t))
				}
				f.reopen(t)
				f.storage.onDelete, f.storage.onAdd = nil, nil
				reads := f.storage.inspected
				f.storage.onAdd = func(Digest, int32) (bool, error) {
					if f.storage.inspected <= reads {
						t.Fatal("repeated mutation without reading")
					}
					return true, nil
				}
				if res, err = turn(t, f.publisher(), f.anchor); err != nil || !res.Done || res.Value != 8 {
					t.Fatalf("recovery res %+v err %v", res, err)
				}
				wantDeletes, wantAdds := 1, 1
				if !applied {
					if mutation == "delete" {
						wantDeletes++
					} else {
						wantAdds++
					}
				}
				if adds, deletes := f.storage.counts(); len(adds) != wantAdds || deletes != wantDeletes {
					t.Fatalf("adds %v deletes %d; want %d adds, %d deletes", adds, deletes, wantAdds, wantDeletes)
				}
			})
		}
	}
}

func TestPublishRejectedAddAtTargetStillRequiresReset(t *testing.T) {
	f := newPublishFixture(t, 8)
	f.storage.onAdd = func(Digest, int32) (bool, error) { return true, ErrRejected }
	res, err := turn(t, f.publisher(), f.anchor)
	if !errors.Is(err, ErrRejected) || res.Done || !f.target(t).ResetPending {
		t.Fatalf("res %+v err %v target %+v", res, err, f.target(t))
	}
	if _, readErr := f.bodies.Read(1, int64(len(f.body)), sha(f.body)); readErr != nil {
		t.Fatal(readErr)
	}
	f.reopen(t)
	f.storage.onAdd = nil
	if res, err = turn(t, f.publisher(), f.anchor); err != nil || !res.Done || res.Value != 8 {
		t.Fatalf("recovery res %+v err %v", res, err)
	}
	if adds, deletes := f.storage.counts(); !reflect.DeepEqual(adds, []int32{8, 8}) || deletes != 1 {
		t.Fatalf("refusal was not reset: adds %v deletes %d", adds, deletes)
	}
}

func TestPublishRejectedDeleteAtTargetStillRequiresReset(t *testing.T) {
	f := newPublishFixture(t, 8)
	f.storage.set(f.anchor, 26)
	f.storage.onDelete = func(Digest) (bool, error) {
		// A late write reaching T does not prove a refused delete left the
		// anchor and its shingles intact.
		f.storage.set(f.anchor, 8)
		return false, ErrRejected
	}
	res, err := turn(t, f.publisher(), f.anchor)
	if !errors.Is(err, ErrRejected) || res.Done || !f.target(t).ResetPending {
		t.Fatalf("res %+v err %v target %+v", res, err, f.target(t))
	}
	f.reopen(t)
	f.storage.onDelete = nil
	if res, err = turn(t, f.publisher(), f.anchor); err != nil || !res.Done || res.Value != 8 {
		t.Fatalf("recovery res %+v err %v", res, err)
	}
	if adds, deletes := f.storage.counts(); !reflect.DeepEqual(adds, []int32{8}) || deletes != 2 {
		t.Fatalf("refusal was not reset: adds %v deletes %d", adds, deletes)
	}
}

func TestPublishJournalFailureSendsNothing(t *testing.T) {
	for _, phase := range []Phase{PhaseRead, PhaseDeletePending, PhaseAddPending} {
		t.Run(string(phase), func(t *testing.T) {
			f := newPublishFixture(t, 8)
			f.editTarget(t, func(cur *Target) { cur.Phase = phase })
			if phase == PhaseDeletePending {
				f.storage.set(f.anchor, 26)
			}
			f.ledger.db = &publishFaultLedger{kv: f.ledger.db, updateErr: errors.New("commit failed")}
			res, err := turn(t, f.publisher(), f.anchor)
			if !errors.Is(err, ErrStateIO) || res.Done {
				t.Fatalf("res %+v err %v", res, err)
			}
			if adds, deletes := f.storage.counts(); len(adds) != 0 || deletes != 0 || f.target(t).Phase != phase {
				t.Fatalf("adds %v deletes %d target %+v", adds, deletes, f.target(t))
			}
		})
	}
}

func TestPublishCompletionFailureRetainsSentPhase(t *testing.T) {
	f := newPublishFixture(t, 8)
	faults := &publishFaultLedger{kv: f.ledger.db}
	f.ledger.db = faults
	f.storage.onAdd = func(Digest, int32) (bool, error) {
		faults.updateErr = errors.New("commit failed")
		return true, nil
	}
	res, err := turn(t, f.publisher(), f.anchor)
	if !errors.Is(err, ErrStateIO) || res.Done || f.target(t).Phase != PhaseAddSent {
		t.Fatalf("res %+v err %v target %+v", res, err, f.target(t))
	}
	faults.updateErr = nil
	f.ledger.db = faults.kv
	f.reopen(t)
	f.storage.onAdd = nil
	if res, err = turn(t, f.publisher(), f.anchor); err != nil || !res.Done || res.Value != 8 {
		t.Fatalf("recovery res %+v err %v", res, err)
	}
	if adds, deletes := f.storage.counts(); !reflect.DeepEqual(adds, []int32{8}) || deletes != 0 {
		t.Fatalf("adds %v deletes %d", adds, deletes)
	}
}

func TestPublishLedgerReadFailureAfterSendIsReported(t *testing.T) {
	f := newPublishFixture(t, 8)
	faults := &publishFaultLedger{kv: f.ledger.db}
	f.ledger.db = faults
	f.storage.onAdd = func(Digest, int32) (bool, error) {
		faults.viewErr = errors.New("read failed")
		return true, ErrUncertain
	}
	res, err := turn(t, f.publisher(), f.anchor)
	if !errors.Is(err, ErrStateIO) || res.Done || !res.Uncertain {
		t.Fatalf("res %+v err %v", res, err)
	}
	faults.viewErr = nil
	if got := f.target(t); got.Phase != PhaseAddSent || got.T != 8 {
		t.Fatalf("target %+v", got)
	}
}

func TestPublishBodyInspectionFailureReportsReadError(t *testing.T) {
	f := newPublishFixture(t, 8)
	f.storage.onInspect = func() { f.storage.readErr = ErrUncertain }
	res, err := turn(t, f.publisher(), f.anchor)
	if !errors.Is(err, ErrReadFailed) || res.Done || res.Uncertain {
		t.Fatalf("res %+v err %v", res, err)
	}
	if adds, deletes := f.storage.counts(); len(adds) != 0 || deletes != 0 || f.target(t).Phase != PhaseRead {
		t.Fatalf("adds %v deletes %d target %+v", adds, deletes, f.target(t))
	}
}

func TestPublishTargetChangedBeforeSend(t *testing.T) {
	f := newPublishFixture(t, 8)
	f.storage.onInspect = func() {
		f.editTarget(t, func(cur *Target) { cur.T, cur.Revision = 0, cur.Revision+1 })
	}
	res, err := turn(t, f.publisher(), f.anchor)
	if !errors.Is(err, errTargetMoved) || res.Done {
		t.Fatalf("res %+v err %v", res, err)
	}
	if adds, deletes := f.storage.counts(); len(adds) != 0 || deletes != 0 {
		t.Fatalf("adds %v deletes %d", adds, deletes)
	}
}

func TestPublishRetryUsesFreshValue(t *testing.T) {
	f := newPublishFixture(t, 8)
	f.storage.set(f.anchor, 2)
	f.storage.onAdd = func(Digest, int32) (bool, error) { return false, ErrUncertain }
	res, err := turn(t, f.publisher(), f.anchor)
	if err != nil || !res.Uncertain || res.Done {
		t.Fatalf("res %+v err %v", res, err)
	}
	f.reopen(t)
	f.storage.set(f.anchor, 4)
	f.storage.onAdd = nil
	if res, err = turn(t, f.publisher(), f.anchor); err != nil || !res.Done || res.Value != 8 {
		t.Fatalf("recovery res %+v err %v", res, err)
	}
	if adds, deletes := f.storage.counts(); !reflect.DeepEqual(adds, []int32{6, 4}) || deletes != 0 {
		t.Fatalf("adds %v deletes %d", adds, deletes)
	}
}

func TestPublishFailedVerificationStaysPending(t *testing.T) {
	for _, failure := range []string{"sync", "read"} {
		t.Run(failure, func(t *testing.T) {
			f := newPublishFixture(t, 8)
			f.storage.onAdd = func(Digest, int32) (bool, error) {
				if failure == "sync" {
					f.storage.syncErr = ErrRejected
				} else {
					f.storage.readErr = ErrRejected
				}
				return true, nil
			}
			res, err := f.publisher().Turn(context.Background(), f.anchor)
			if err != nil || !res.Uncertain || res.Done || res.Phase != PhaseAddSent {
				t.Fatalf("res %+v err %v", res, err)
			}
			if got := f.target(t); got.Phase != PhaseAddSent || got.T != 8 {
				t.Fatalf("target %+v", got)
			}
		})
	}
}
