package store

import (
	"reflect"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	bolt "go.etcd.io/bbolt"
)

// Tick refills history credit from elapsed time: a lane that ran dry
// admits again once it has earned the cost, and not a second before.
func TestAdmissionLedgerTickRefillsHistory(t *testing.T) {
	general, _ := admission.HistoryLanes()
	f := newLedgerFixture(t)
	id := f.queued()
	cost := f.cost(id)
	f.adjustStorage(func(s *admission.StorageState) { s.General.Credit = 0 })
	rate := admission.HistoryRate(general)
	wait := time.Duration((uint64(cost) + rate - 1) / rate * uint64(time.Second))
	f.tickAt(f.wall.Add(wait - time.Second))
	if got := f.storageState().General.Credit; got != rate*uint64(wait-time.Second) {
		t.Fatalf("credit after %v = %d ticks, want %d", wait-time.Second, got, rate*uint64(wait-time.Second))
	}
	_, _, _, err := f.l.Reserve(id, admission.LaneGeneral, f.wall.Add(time.Hour))
	wantLedgerReason(t, "a second short of the cost", err, admission.ReasonStorageShare)
	f.tickAt(f.wall.Add(time.Second))
	if _, _, _, err = f.l.Reserve(id, admission.LaneGeneral, f.wall.Add(time.Hour)); err != nil {
		t.Fatalf("after the refill: %v", err)
	}
}

// Ended history is retired at its target without any pressure: thirty
// days after it ended, or when a longer effect ends. A pinned outcome is
// never retired this way.
func TestAdmissionLedgerTickRetiresAtTheTarget(t *testing.T) {
	f := newLedgerFixture(t)
	short := f.applied(time.Hour)
	long := f.applied(40 * 24 * time.Hour)
	pinned, a := f.admitted(time.Hour)
	if _, _, _, err := f.l.Execute(a.Attempt.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.l.Finish(a.Attempt.ID, admission.DispositionUnknown); err != nil {
		t.Fatal(err)
	}
	ended := f.wall
	f.ackAll()
	used, shortCost := f.storageState().General.Used, f.cost(short)
	f.tickAt(ended.Add(admission.HistoryTarget - time.Nanosecond))
	if _, err := f.l.Candidate(short); err != nil {
		t.Fatalf("retired before its target: %v", err)
	}
	f.tickAt(ended.Add(admission.HistoryTarget))
	if _, err := f.l.Candidate(short); err != errCandidateMissing {
		t.Fatalf("at its target: %v", err)
	}
	if got := f.storageState().General.Used; got != used-uint64(shortCost) {
		t.Fatalf("usage after the first retirement = %d, want %d", got, used-uint64(shortCost))
	}
	f.tickAt(ended.Add(40 * 24 * time.Hour).Add(-time.Nanosecond))
	if _, err := f.l.Candidate(long); err != nil {
		t.Fatalf("a long effect retired before it ended: %v", err)
	}
	f.tickAt(ended.Add(40 * 24 * time.Hour))
	if _, err := f.l.Candidate(long); err != errCandidateMissing {
		t.Fatalf("a long effect after it ended: %v", err)
	}
	if s := f.storageState(); s.General.Used != 0 || s.Recovery == 0 {
		t.Fatalf("storage after both retirements = %+v", s)
	}
	f.tickAt(ended.Add(365 * 24 * time.Hour))
	if _, err := f.l.Candidate(pinned); err != nil {
		t.Fatalf("a pinned outcome was retired: %v", err)
	}
}

// One tick retires a bounded batch; the next continues where it stopped.
func TestAdmissionLedgerTickRetiresABoundedBatch(t *testing.T) {
	f := newLedgerFixture(t)
	var ids []admission.CandidateID
	for i := 0; i < retirementsPerTick+3; i++ {
		ids = append(ids, f.applied(time.Hour))
		// The next reservation waits for the history credit it needs.
		f.tickAt(f.wall.Add(10 * time.Second))
	}
	f.ackAll()
	f.tickAt(f.wall.Add(admission.HistoryTarget))
	var kept int
	for _, id := range ids {
		if _, err := f.l.Candidate(id); err == nil {
			kept++
		}
	}
	if kept != 3 {
		t.Fatalf("one tick left %d of %d at their target, want 3", kept, len(ids))
	}
	f.tickAt(f.wall.Add(time.Second))
	for _, id := range ids {
		if _, err := f.l.Candidate(id); err != errCandidateMissing {
			t.Fatalf("%s after the second tick: %v", id, err)
		}
	}
}

// The history refill and retirement commit with the clock or not at all.
func TestAdmissionLedgerTickMetersStorageAtomically(t *testing.T) {
	f := newLedgerFixture(t)
	f.applied(time.Hour)
	f.adjustStorage(func(s *admission.StorageState) { s.General.Credit = 0 })
	before := f.snapshot()
	f.failNext("tick")
	if _, err := f.l.Tick(admission.ClockReading{Wall: f.wall.Add(admission.HistoryTarget), BootID: ledgerBoot, SinceBoot: f.since + admission.HistoryTarget}); err == nil {
		t.Fatal("injected failure did not abort the tick")
	}
	if !reflect.DeepEqual(before, f.snapshot()) {
		t.Fatal("a failed tick changed storage")
	}
}

// A damaged storage record stops time, as a damaged ceiling does, while
// the outcome of running work that needs no storage change is still
// recorded.
func TestAdmissionLedgerDamagedStorageRefusesTick(t *testing.T) {
	f := newLedgerFixture(t)
	id, a := f.admitted(time.Hour)
	if _, _, _, err := f.l.Execute(a.Attempt.ID); err != nil {
		t.Fatal(err)
	}
	if err := f.db.bolt.Update(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte(admissionQueueStateBucket)).Put(storageStateKey, []byte("damaged"))
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.l.Tick(admission.ClockReading{Wall: f.wall.Add(time.Second), BootID: ledgerBoot, SinceBoot: f.since + time.Second}); !isCorrupt(err) {
		t.Fatalf("tick over damaged storage: %v", err)
	}
	if c, _, err := f.l.Finish(a.Attempt.ID, admission.DispositionApplied); err != nil || c.State != admission.StateVerified {
		t.Fatalf("finish over damaged storage: %+v, %v", c, err)
	}
	if h, _ := f.historyEntry(id); h.Ended.IsZero() {
		t.Fatalf("the outcome did not date its history: %+v", h)
	}
}

// A final failure of work that ran is recorded over a damaged storage
// record too (1.3b-4 decision 10): its notice cannot take a new record,
// which needs storage, so it counts in its kind's fixed overflow record and
// in the Critical summary.
func TestAdmissionLedgerFinalFailureOverDamagedStorage(t *testing.T) {
	f := newLedgerFixture(t)
	id := f.criticalQueued()
	var a admission.AttemptRecord
	var err error
	for seq := uint32(1); seq <= admission.MaxAttempts; seq++ {
		if seq > 1 {
			f.tickAt(f.wall.Add(admission.RetryBackoff(seq - 1)))
		}
		expires := time.Time{}
		if seq == 1 {
			expires = f.wall.Add(3 * time.Hour)
		}
		if _, a, _, err = f.l.Reserve(id, admission.LaneGeneral, expires); err != nil {
			t.Fatal(err)
		}
		if _, _, _, err = f.l.Execute(a.Attempt.ID); err != nil {
			t.Fatal(err)
		}
		if seq < admission.MaxAttempts {
			if _, _, err = f.l.Finish(a.Attempt.ID, admission.DispositionFailed); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err = f.db.bolt.Update(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte(admissionQueueStateBucket)).Put(storageStateKey, []byte("damaged"))
	}); err != nil {
		t.Fatal(err)
	}
	c, done, err := f.l.Finish(a.Attempt.ID, admission.DispositionFailed)
	if err != nil || c.State != admission.StateFailed || done.State != admission.StateFailed {
		t.Fatalf("final failure over damaged storage: %+v %+v, %v", c, done, err)
	}
	notices := f.notices()
	if r := notices[admission.OverflowKey(admission.NoticeWithheld)]; r.Count != 1 {
		t.Fatalf("overflow record = %+v", r)
	}
	if r := notices[admission.NoticeKey{Kind: admission.NoticeCriticalSummary}]; r.Count != 1 {
		t.Fatalf("Critical summary = %+v", r)
	}
}
