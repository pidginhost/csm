package learn

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func turn(t *testing.T, p *Publisher, d Digest) (TurnResult, error) {
	t.Helper()
	return p.Turn(context.Background(), d)
}

func TestPublishFreshAnchor(t *testing.T) {
	f := newPublishFixture(t, 2)
	res, err := turn(t, f.publisher(), f.anchor)
	if err != nil || !res.Done || res.Value != 2 {
		t.Fatalf("res %+v err %v", res, err)
	}
	adds, deletes := f.storage.counts()
	if !reflect.DeepEqual(adds, []int32{2}) || deletes != 0 || f.storage.syncs == 0 {
		t.Fatalf("adds %v deletes %d syncs %d", adds, deletes, f.storage.syncs)
	}
	if got := f.target(t); got.Phase != PhaseIdle || got.T != 2 {
		t.Fatalf("target %+v", got)
	}
}

func TestPublishRaise(t *testing.T) {
	f := newPublishFixture(t, 6)
	f.storage.set(f.anchor, 4)
	res, err := turn(t, f.publisher(), f.anchor)
	if err != nil || !res.Done || res.Value != 6 {
		t.Fatalf("res %+v err %v", res, err)
	}
	if adds, deletes := f.storage.counts(); !reflect.DeepEqual(adds, []int32{2}) || deletes != 0 {
		t.Fatalf("adds %v deletes %d", adds, deletes)
	}
}

func TestPublishLowerUsesDeleteThenAdd(t *testing.T) {
	f := newPublishFixture(t, 8)
	f.storage.set(f.anchor, 26)
	res, err := turn(t, f.publisher(), f.anchor)
	if err != nil || !res.Done || res.Value != 8 {
		t.Fatalf("res %+v err %v", res, err)
	}
	if adds, deletes := f.storage.counts(); !reflect.DeepEqual(adds, []int32{8}) || deletes != 1 {
		t.Fatalf("adds %v deletes %d", adds, deletes)
	}
	if got := f.target(t); got.Phase != PhaseIdle || got.ResetPending || got.RestoreT != 0 {
		t.Fatalf("target %+v", got)
	}
}

func TestPublishZeroTargetDeletesOnly(t *testing.T) {
	f := newPublishFixture(t, 0)
	f.storage.set(f.anchor, 6)
	res, err := turn(t, f.publisher(), f.anchor)
	if err != nil || !res.Done {
		t.Fatalf("res %+v err %v", res, err)
	}
	if _, present := f.storage.value(f.anchor); present {
		t.Fatal("zero target still stored")
	}
	if adds, deletes := f.storage.counts(); len(adds) != 0 || deletes != 1 {
		t.Fatalf("adds %v deletes %d", adds, deletes)
	}
}

// Review focus 1: an add applied by storage whose reply was lost, then a
// restart. Recovery reads the exact value before anything else.
func TestPublishLostReplyThenCrashNoDoubleAdd(t *testing.T) {
	f := newPublishFixture(t, 2)
	f.storage.onAdd = func(Digest, int32) (bool, error) { return true, ErrUncertain }
	res, err := turn(t, f.publisher(), f.anchor)
	if err != nil || res.Done || !res.Uncertain || f.target(t).Phase != PhaseAddSent {
		t.Fatalf("res %+v err %v target %+v", res, err, f.target(t))
	}
	f.storage.onAdd = nil
	// A new publisher, as after a daemon restart, built only from the ledger.
	res, err = turn(t, f.publisher(), f.anchor)
	if err != nil || !res.Done || res.Value != 2 {
		t.Fatalf("recovery res %+v err %v", res, err)
	}
	if adds, _ := f.storage.counts(); len(adds) != 1 {
		t.Fatalf("sent %d adds", len(adds))
	}
}

func TestPublishAckedThenLostBeforeFlush(t *testing.T) {
	f := newPublishFixture(t, 6)
	f.storage.set(f.anchor, 4)
	f.storage.onAdd = func(Digest, int32) (bool, error) { return false, nil }
	res, err := turn(t, f.publisher(), f.anchor)
	if err != nil || res.Done || !res.Uncertain {
		t.Fatalf("res %+v err %v", res, err)
	}
	f.storage.onAdd = nil
	if res, err = turn(t, f.publisher(), f.anchor); err != nil || !res.Done || res.Value != 6 {
		t.Fatalf("res %+v err %v", res, err)
	}
	// One new add of T-V, never a repeat of an old delta plus another.
	if adds, _ := f.storage.counts(); !reflect.DeepEqual(adds, []int32{2, 2}) {
		t.Fatalf("adds %v", adds)
	}
}

func TestPublishReadFailureSendsNothing(t *testing.T) {
	f := newPublishFixture(t, 2)
	f.storage.readErr = errors.New("timeout")
	res, err := turn(t, f.publisher(), f.anchor)
	if !errors.Is(err, ErrReadFailed) || res.Done {
		t.Fatalf("res %+v err %v", res, err)
	}
	if adds, deletes := f.storage.counts(); len(adds) != 0 || deletes != 0 {
		t.Fatalf("adds %v deletes %d", adds, deletes)
	}
	if got := f.target(t); got.Phase != PhaseRead {
		t.Fatalf("phase moved to %s", got.Phase)
	}
}

func TestPublishNonPositiveValueNeedsReset(t *testing.T) {
	f := newPublishFixture(t, 2)
	f.storage.set(f.anchor, 0)
	res, err := turn(t, f.publisher(), f.anchor)
	if err != nil || !res.Done || res.Value != 2 {
		t.Fatalf("res %+v err %v", res, err)
	}
	if adds, deletes := f.storage.counts(); !reflect.DeepEqual(adds, []int32{2}) || deletes != 1 {
		t.Fatalf("a zero hit was not deleted and rebuilt: adds %v deletes %d", adds, deletes)
	}
}

func TestPublishDeleteSucceedsAddFails(t *testing.T) {
	f := newPublishFixture(t, 8)
	f.storage.set(f.anchor, 26)
	f.storage.onAdd = func(Digest, int32) (bool, error) { return false, ErrRejected }
	res, err := turn(t, f.publisher(), f.anchor)
	if !errors.Is(err, ErrRejected) || res.Done {
		t.Fatalf("res %+v err %v", res, err)
	}
	got := f.target(t)
	if got.Phase != PhaseAddPending || got.RestoreT != 8 || got.T != 8 {
		t.Fatalf("target %+v", got)
	}
	if _, readErr := f.bodies.Read(1, int64(len(f.body)), sha(f.body)); readErr != nil {
		t.Fatalf("body lost: %v", readErr)
	}
	f.storage.onAdd = nil
	if res, err = turn(t, f.publisher(), f.anchor); err != nil || !res.Done || res.Value != 8 {
		t.Fatalf("restore res %+v err %v", res, err)
	}
	if _, deletes := f.storage.counts(); deletes != 1 {
		t.Fatalf("deletion restarted: %d deletes", deletes)
	}
}

func TestPublishBodyInvalidBlocks(t *testing.T) {
	f := newPublishFixture(t, 2)
	if err := os.WriteFile(filepath.Join(f.bodies.Dir, BodyName(1)), []byte("changed bytes!"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := turn(t, f.publisher(), f.anchor); !errors.Is(err, ErrBodyInvalid) {
		t.Fatalf("err %v", err)
	}
	if adds, _ := f.storage.counts(); len(adds) != 0 {
		t.Fatal("published a changed body")
	}
}

func TestPublishGenerationChangedBlocks(t *testing.T) {
	f := newPublishFixture(t, 2)
	f.storage.bodies[string(f.body)] = digest('n') // new hash keys, new digest
	if _, err := turn(t, f.publisher(), f.anchor); !errors.Is(err, ErrStateMismatch) {
		t.Fatalf("err %v", err)
	}
	if adds, _ := f.storage.counts(); len(adds) != 0 {
		t.Fatal("published under a changed hash generation")
	}
}

func TestPublishPersistsPhaseBeforeSend(t *testing.T) {
	f := newPublishFixture(t, 8)
	f.storage.set(f.anchor, 26)
	var atDelete, atAdd Phase
	f.storage.onDelete = func(Digest) (bool, error) {
		atDelete = f.target(t).Phase
		return true, nil
	}
	f.storage.onAdd = func(Digest, int32) (bool, error) {
		atAdd = f.target(t).Phase
		return true, nil
	}
	if res, err := turn(t, f.publisher(), f.anchor); err != nil || !res.Done {
		t.Fatalf("res %+v err %v", res, err)
	}
	if atDelete != PhaseDeleteSent || atAdd != PhaseAddSent {
		t.Fatalf("phase at delete %s, at add %s", atDelete, atAdd)
	}
}

func (f *publishFixture) editTarget(t *testing.T, edit func(*Target)) {
	t.Helper()
	if err := f.ledger.Update(func(tx LedgerTx) error {
		cur, ok, err := tx.Target(f.anchor)
		if err != nil {
			return err
		}
		if !ok {
			return errors.New("fixture target missing")
		}
		edit(&cur)
		return tx.PutTarget(cur)
	}); err != nil {
		t.Fatal(err)
	}
}

func TestPublishZeroTargetRequiresAbsenceInEveryPhase(t *testing.T) {
	phases := []Phase{PhaseIdle, PhaseRead, PhaseAddSent, PhaseDeletePending, PhaseDeleteSent, PhaseAddPending}
	for _, phase := range phases {
		for _, reset := range []bool{false, true} {
			for _, value := range []int64{-1, 0, 2} {
				t.Run(fmt.Sprintf("%s/reset=%t/value=%d", phase, reset, value), func(t *testing.T) {
					f := newPublishFixture(t, 0)
					// -1 denotes absence; a stored zero is still a hit.
					if value >= 0 {
						f.storage.set(f.anchor, value)
					}
					f.editTarget(t, func(cur *Target) {
						cur.Phase, cur.ResetPending, cur.RestoreT = phase, reset, 2
					})
					// Forget may already have removed the body; only the digest is needed.
					if err := f.bodies.Remove(1); err != nil {
						t.Fatal(err)
					}
					res, err := turn(t, f.publisher(), f.anchor)
					if err != nil || !res.Done || res.Value != 0 || res.Phase != PhaseIdle {
						t.Fatalf("res %+v err %v", res, err)
					}
					if _, present := f.storage.value(f.anchor); present {
						t.Fatal("completed while the zero target was still present")
					}
					wantDeletes := 0
					if value >= 0 {
						wantDeletes = 1
					}
					if adds, deletes := f.storage.counts(); len(adds) != 0 || deletes != wantDeletes {
						t.Fatalf("adds %v deletes %d; want no adds, %d deletes", adds, deletes, wantDeletes)
					}
					if got := f.target(t); got.ResetPending || got.RestoreT != 0 || got.T != 0 {
						t.Fatalf("target %+v", got)
					}
				})
			}
		}
	}
}

func TestPublishExactTargetAndRequiredReset(t *testing.T) {
	phases := []Phase{PhaseIdle, PhaseRead, PhaseAddSent, PhaseDeletePending, PhaseDeleteSent, PhaseAddPending}
	for _, phase := range phases {
		for _, reset := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/reset=%t", phase, reset), func(t *testing.T) {
				f := newPublishFixture(t, 8)
				f.storage.set(f.anchor, 8)
				f.editTarget(t, func(cur *Target) {
					cur.Phase, cur.ResetPending, cur.RestoreT = phase, reset, 8
				})
				res, err := turn(t, f.publisher(), f.anchor)
				if err != nil || !res.Done || res.Value != 8 {
					t.Fatalf("res %+v err %v", res, err)
				}
				adds, deletes := f.storage.counts()
				// A resumed reset add may finish, but add_pending must delete a new hit.
				mustReset := phase == PhaseAddPending || reset && phase != PhaseAddSent
				if mustReset {
					if !reflect.DeepEqual(adds, []int32{8}) || deletes != 1 {
						t.Fatalf("reset unfinished: adds %v deletes %d", adds, deletes)
					}
				} else if len(adds) != 0 || deletes != 0 {
					t.Fatalf("exact target mutated: adds %v deletes %d", adds, deletes)
				}
				if got := f.target(t); got.Phase != PhaseIdle || got.ResetPending || got.RestoreT != 0 {
					t.Fatalf("target %+v", got)
				}
			})
		}
	}
}

// An add's weight is T-V; a value outside [0, T) never becomes a send.
func TestSendAddRefusesOutOfRangeDelta(t *testing.T) {
	f := newPublishFixture(t, 2)
	p := f.publisher()
	for _, v := range []int64{2, 5, -1, 1 << 40} {
		if _, err := p.sendAdd(context.Background(), f.target(t), v); err == nil {
			t.Fatalf("value %d accepted", v)
		}
	}
	if adds, _ := f.storage.counts(); len(adds) != 0 {
		t.Fatalf("sent adds %v", adds)
	}
}
