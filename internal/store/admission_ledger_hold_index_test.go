package store

import (
	"maps"
	"math"
	"reflect"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	bolt "go.etcd.io/bbolt"
)

// storedHolds derives the recovery hold from the stored records the way
// the hold was read before the index: every intent whose attempt is
// unresolved holds its target key.
func storedHolds(t testing.TB, db *DB) map[string]int {
	t.Helper()
	out := map[string]int{}
	if err := db.bolt.View(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte(admissionIntentsBucket)).ForEach(func(_, v []byte) error {
			in, err := admission.UnmarshalIntent(v)
			if err != nil {
				return err
			}
			a, err := loadAttempt(tx, in.Action)
			if err != nil {
				return err
			}
			if a.State == admission.StateExecuting || (a.State == admission.StateUnknown && !a.Retired) {
				out[in.Target.Key()]++
			}
			return nil
		})
	}); err != nil {
		t.Fatal(err)
	}
	return out
}

// publishedHolds is the index a handle reads instead.
func publishedHolds(l *AdmissionLedger) map[string]int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return maps.Clone(l.held)
}

func wantHolds(t *testing.T, step string, l *AdmissionLedger, db *DB, keys int) {
	t.Helper()
	got, want := publishedHolds(l), storedHolds(t, db)
	if len(want) != keys {
		t.Fatalf("%s: fixture holds %d targets, want %d", step, len(want), keys)
	}
	if !maps.Equal(got, want) {
		t.Fatalf("%s: published hold %v, stored records hold %v", step, got, want)
	}
}

// Each handle derives the hold once at open and changes it with every
// committed transaction that writes or deletes an intent: running,
// unknown, applied, retired and settled attempts, and a reopened handle.
func TestAdmissionLedgerHoldIndexFollowsEveryChange(t *testing.T) {
	f := newLedgerFixture(t)
	wantHolds(t, "open", f.l, f.db, 0)
	a := f.reservedAt("192.0.2.10", ledgerT0.Add(time.Hour))
	b := f.reservedAt("192.0.2.11", ledgerT0.Add(time.Hour))
	wantHolds(t, "reserve", f.l, f.db, 0)
	if _, _, err := f.l.ExecuteBatch([]admission.ActionID{a.Attempt.ID, b.Attempt.ID}); err != nil {
		t.Fatal(err)
	}
	wantHolds(t, "execute", f.l, f.db, 2)
	if _, _, err := f.l.Finish(a.Attempt.ID, admission.DispositionUnknown); err != nil {
		t.Fatal(err)
	}
	wantHolds(t, "unknown", f.l, f.db, 2)
	if _, _, err := f.l.Finish(b.Attempt.ID, admission.DispositionApplied); err != nil {
		t.Fatal(err)
	}
	wantHolds(t, "applied", f.l, f.db, 1)
	f.ackAll()
	f.tickAt(a.ExpiresAt)
	if _, _, retired, err := f.l.RetireUnproven(a.Attempt.ID); err != nil || !retired {
		t.Fatalf("retire: %v %v", retired, err)
	}
	wantHolds(t, "retired", f.l, f.db, 0)

	c := f.reservedAt("192.0.2.12", f.wall.Add(time.Hour))
	if _, _, err := f.l.ExecuteBatch([]admission.ActionID{c.Attempt.ID}); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenAdmissionLedger(f.db, f.reg)
	if err != nil {
		t.Fatal(err)
	}
	wantHolds(t, "reopen", reopened, f.db, 1)
	if _, unknown, err := reopened.Settle(); err != nil || unknown != 1 {
		t.Fatalf("settle: %d unknown, %v", unknown, err)
	}
	wantHolds(t, "settled", reopened, f.db, 1)
}

// A transaction that does not commit leaves the published hold as it was.
func TestAdmissionLedgerHoldIndexWaitsForCommit(t *testing.T) {
	f := newLedgerFixture(t)
	a := f.reservedAt("192.0.2.10", ledgerT0.Add(time.Hour))
	f.failNext("execute")
	if _, _, err := f.l.ExecuteBatch([]admission.ActionID{a.Attempt.ID}); err == nil {
		t.Fatal("failed execute reported success")
	}
	wantHolds(t, "failed execute", f.l, f.db, 0)
	if _, _, err := f.l.ExecuteBatch([]admission.ActionID{a.Attempt.ID}); err != nil {
		t.Fatal(err)
	}
	f.failNext("finish")
	if _, _, err := f.l.Finish(a.Attempt.ID, admission.DispositionApplied); err == nil {
		t.Fatal("failed finish reported success")
	}
	wantHolds(t, "failed finish", f.l, f.db, 1)
}

// fullReserve fills the recovery reserve with unknown outcomes, each with
// its intent (the fixture gives them one target), and queues work the
// schedule must check against the hold.
func fullReserve(b *testing.B) *ledgerFixture {
	b.Helper()
	f := historyFixture(b, false, math.MaxUint32)
	l, err := OpenAdmissionLedger(f.db, f.reg)
	if err != nil {
		b.Fatal(err)
	}
	f.l = l
	f.tickAt(f.wall.Add(time.Second))
	f.fillRoots(admission.MaxBatchMembers, 1)
	held := 0
	for _, n := range publishedHolds(f.l) {
		held += n
	}
	if held < 10000 {
		b.Fatalf("reserve holds %d unresolved outcomes", held)
	}
	return f
}

// The hold at a full recovery reserve costs a map lookup per candidate,
// not a walk of every intent and its attempt per transaction. These
// measure and do not gate.
func BenchmarkAdmissionLedgerScheduleFullReserve(b *testing.B) {
	f := fullReserve(b)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := f.l.Schedule(fullSchedule); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkAdmissionLedgerNextWakeFullReserve(b *testing.B) {
	f := fullReserve(b)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, _, err := f.l.NextWake(); err != nil {
			b.Fatal(err)
		}
	}
}

// Every reservation is refused for room in the full reserve, after the
// hold is read.
func BenchmarkAdmissionLedgerReserveFullReserve(b *testing.B) {
	f := fullReserve(b)
	id := f.queuedIDs()[0]
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, granted, err := f.l.Reserve(id, admission.LaneGeneral, f.wall.Add(time.Hour))
		if granted {
			b.Fatal("a full reserve granted a reservation")
		}
		if _, refused := admission.ReasonOf(err); !refused {
			b.Fatal(err)
		}
	}
}

func TestAdmissionLedgerHoldIndexRollsBackRetirement(t *testing.T) {
	f := newLedgerFixture(t)
	u := f.unknownAt("192.0.2.10", ledgerT0.Add(time.Hour))
	f.ackAll()
	f.tickAt(u.ExpiresAt)
	before := f.snapshot()
	f.failNext("retire")
	if _, _, retired, err := f.l.RetireUnproven(u.Attempt.ID); retired || err == nil || err.Error() != "injected failure before commit" {
		t.Fatalf("retire: %v %v", retired, err)
	}
	if !reflect.DeepEqual(f.snapshot(), before) {
		t.Fatal("failed retirement changed the ledger")
	}
	wantHolds(t, "failed retire", f.l, f.db, 1)
	f.l.mu.Lock()
	pending := f.l.heldDelta != nil
	f.l.mu.Unlock()
	if pending {
		t.Fatal("failed transaction retained its hold delta")
	}
	if _, _, retired, err := f.l.RetireUnproven(u.Attempt.ID); err != nil || !retired {
		t.Fatalf("retry retire: %v %v", retired, err)
	}
	wantHolds(t, "retire retry", f.l, f.db, 0)
}

func TestAdmissionLedgerHoldIndexIncludesUpgradedIntents(t *testing.T) {
	f := newLedgerFixture(t)
	a := f.reservedAt("192.0.2.10", ledgerT0.Add(time.Hour))
	if _, _, _, err := f.l.Execute(a.Attempt.ID); err != nil {
		t.Fatal(err)
	}
	f.unknownAt("192.0.2.11", ledgerT0.Add(time.Hour))
	f.reservedAt("192.0.2.12", ledgerT0.Add(time.Hour))
	f.schemaSix()
	l, err := OpenAdmissionLedger(f.db, f.reg)
	if err != nil {
		t.Fatal(err)
	}
	wantHolds(t, "schema-seven upgrade", l, f.db, 2)
}

func TestAdmissionLedgerHoldIndexNextWakeWithConcurrentTransitions(t *testing.T) {
	f := newLedgerFixture(t)
	f.fillRoots(16, 1)
	var actions []admission.ActionID
	for _, id := range f.queuedIDs() {
		_, a, granted, err := f.l.Reserve(id, admission.LaneGeneral, f.wall.Add(time.Hour))
		if err != nil || !granted {
			t.Fatalf("reserve: %v %v", granted, err)
		}
		actions = append(actions, a.Attempt.ID)
	}
	f.queued()
	start, done := make(chan struct{}), make(chan error, 2)
	go func() {
		<-start
		for range 64 {
			if _, _, err := f.l.NextWake(); err != nil {
				done <- err
				return
			}
		}
		done <- nil
	}()
	go func() {
		<-start
		for _, id := range actions {
			if _, _, _, err := f.l.Execute(id); err != nil {
				done <- err
				return
			}
			if _, _, err := f.l.Finish(id, admission.DispositionApplied); err != nil {
				done <- err
				return
			}
		}
		done <- nil
	}()
	close(start)
	for range 2 {
		select {
		case err := <-done:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("NextWake and transitions did not complete")
		}
	}
	wantHolds(t, "concurrent transitions", f.l, f.db, 0)
}
