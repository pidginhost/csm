package store

import (
	"fmt"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	bolt "go.etcd.io/bbolt"
)

// A deferral reason is recorded once; the same reason again is not another
// transition, and only deferral reasons defer.
func TestAdmissionLedgerDefer(t *testing.T) {
	f := newLedgerFixture(t)
	id := f.queued()
	c, err := f.l.Defer(id, admission.ReasonCeiling)
	if err != nil || c.Reason != admission.ReasonCeiling || c.Transitions != 2 {
		t.Fatalf("defer: %+v, %v", c, err)
	}
	if again, againErr := f.l.Defer(id, admission.ReasonCeiling); againErr != nil || again.Transitions != 2 {
		t.Fatalf("repeat defer: %+v, %v", again, againErr)
	}
	if c, _ = f.l.Defer(id, admission.ReasonSetFull); c.Transitions != 3 {
		t.Fatalf("changed reason transitions = %d", c.Transitions)
	}
	_, err = f.l.Defer(id, admission.ReasonProtected)
	wantLedgerReason(t, "refusal as deferral", err, admission.ReasonInvalid)
}

// Termination records the reason's own group; the same ending is a no-op
// and a different one conflicts.
func TestAdmissionLedgerTerminate(t *testing.T) {
	f := newLedgerFixture(t)
	for reason, state := range map[admission.Reason]admission.State{
		admission.ReasonProtected:     admission.StateRefused,
		admission.ReasonCollateral:    admission.StateWithheld,
		admission.ReasonQueueOverflow: admission.StateDropped,
	} {
		id := f.queued()
		c, err := f.l.Terminate(id, reason)
		if err != nil || c.State != state || c.Disposition != reason.Disposition() || c.Reason != reason {
			t.Fatalf("%s: %+v, %v", reason, c, err)
		}
		if again, againErr := f.l.Terminate(id, reason); againErr != nil || again.Transitions != c.Transitions {
			t.Fatalf("%s: repeat: %+v, %v", reason, again, againErr)
		}
		_, err = f.l.Terminate(id, admission.ReasonStale)
		wantLedgerErr(t, reason.String()+": different ending", err, admission.ErrCandidateTerminal)
		_, _, _, err = f.l.Reserve(id, ledgerT0.Add(time.Hour))
		wantLedgerErr(t, reason.String()+": reserve after end", err, admission.ErrCandidateTerminal)
		root := f.published(evidenceSpec{cursor: fmt.Sprintf("offset=%d", f.generation+1)})
		_, _, err = f.l.Enqueue(f.request("192.0.2.10", root))
		wantLedgerErr(t, reason.String()+": enqueue after end", err, admission.ErrCandidateTerminal)
		f.nextGeneration()
	}
	_, err := f.l.Terminate(f.queued(), admission.ReasonCeiling)
	wantLedgerReason(t, "deferral as ending", err, admission.ReasonInvalid)
}

// The first reservation fixes the absolute expiry. Reserving a reserved
// candidate again returns the same attempt, so recovery reuses its ID.
func TestAdmissionLedgerReserveAndRecover(t *testing.T) {
	f := newLedgerFixture(t)
	id := f.queued()
	expires := ledgerT0.Add(24 * time.Hour)
	for name, at := range map[string]time.Time{"no expiry": {}, "expiry now": ledgerT0} {
		_, _, _, err := f.l.Reserve(id, at)
		wantLedgerReason(t, name, err, admission.ReasonInvalid)
	}
	c, a, _, err := f.l.Reserve(id, expires)
	if err != nil || c.State != admission.StateReserved || c.Attempts != 1 || !c.ExpiresAt.Equal(expires) {
		t.Fatalf("reserve: %+v, %v", c, err)
	}
	if a.Attempt.Seq != 1 || a.Attempt.Prev != "" || a.State != admission.StateReserved || !a.Reserved.Equal(ledgerT0) {
		t.Fatalf("attempt: %+v", a)
	}
	again, same, _, err := f.l.Reserve(id, time.Time{})
	if err != nil || same != a || again.Transitions != c.Transitions {
		t.Fatalf("recovery: %+v %+v, %v", again, same, err)
	}
	_, _, _, err = f.l.Reserve(id, expires.Add(time.Hour))
	wantLedgerErr(t, "changed expiry", err, admission.ErrTransitionConflict)
	if _, running, _, err := f.l.Execute(a.Attempt.ID); err != nil || running.State != admission.StateExecuting {
		t.Fatalf("execute: %+v, %v", running, err)
	}
	if _, running, _, err := f.l.Execute(a.Attempt.ID); err != nil || running.State != admission.StateExecuting {
		t.Fatalf("repeat execute: %+v, %v", running, err)
	}
	if _, same, _, err := f.l.Reserve(id, expires); err != nil || same.Attempt != a.Attempt {
		t.Fatalf("recovery while executing: %+v, %v", same, err)
	}
}

// A proven failure requeues the candidate behind a backoff, keeping its
// expiry; the next attempt links to the failed one; the last allowed
// failure ends the candidate.
func TestAdmissionLedgerRetriesProvenFailures(t *testing.T) {
	f := newLedgerFixture(t)
	id := f.queued()
	expires := ledgerT0.Add(24 * time.Hour)
	var prev admission.ActionID
	for seq := uint32(1); seq <= admission.MaxAttempts; seq++ {
		want := time.Time{}
		if seq == 1 {
			want = expires
		}
		_, a, _, err := f.l.Reserve(id, want)
		if err != nil || a.Attempt.Seq != seq || a.Attempt.Prev != prev || !a.ExpiresAt.Equal(expires) {
			t.Fatalf("attempt %d: %+v, %v", seq, a, err)
		}
		if seq == 2 {
			// A failure before execution is still a proven failure.
			c, done, finishErr := f.l.Finish(a.Attempt.ID, admission.DispositionFailed)
			if finishErr != nil || done.State != admission.StateFailed || c.State != admission.StateQueued {
				t.Fatalf("failure before execution: %+v %+v, %v", c, done, finishErr)
			}
		} else {
			if _, _, _, err = f.l.Execute(a.Attempt.ID); err != nil {
				t.Fatal(err)
			}
			c, done, finishErr := f.l.Finish(a.Attempt.ID, admission.DispositionFailed)
			if finishErr != nil || done.State != admission.StateFailed || done.Disposition != admission.DispositionFailed {
				t.Fatalf("attempt %d outcome: %+v, %v", seq, done, finishErr)
			}
			if seq < admission.MaxAttempts {
				if c.State != admission.StateQueued || !c.NotBefore.Equal(f.wall.Add(admission.RetryBackoff(seq))) {
					t.Fatalf("requeue after %d: %+v", seq, c)
				}
			} else if c.State != admission.StateFailed || c.Disposition != admission.DispositionFailed {
				t.Fatalf("exhausted: %+v", c)
			}
		}
		if seq < admission.MaxAttempts {
			_, _, _, err = f.l.Reserve(id, time.Time{})
			wantLedgerErr(t, "reserve before backoff", err, admission.ErrNotReady)
			f.tickAt(f.wall.Add(admission.RetryBackoff(seq)))
			_, _, _, err = f.l.Reserve(id, expires.Add(time.Hour))
			wantLedgerErr(t, "retry with a new expiry", err, admission.ErrTransitionConflict)
		}
		prev = a.Attempt.ID
	}
	_, _, _, err := f.l.Reserve(id, time.Time{})
	wantLedgerErr(t, "reserve after exhaustion", err, admission.ErrCandidateTerminal)
}

// Only a running attempt can apply, narrow or end unknown; an unknown
// outcome is never retried; a repeated outcome is idempotent and a
// different one conflicts.
func TestAdmissionLedgerOutcomes(t *testing.T) {
	f := newLedgerFixture(t)
	id := f.queued()
	_, a, _, _ := f.l.Reserve(id, ledgerT0.Add(time.Hour))
	for _, d := range []admission.Disposition{admission.DispositionApplied, admission.DispositionUnknown} {
		_, _, err := f.l.Finish(a.Attempt.ID, d)
		wantLedgerErr(t, d.String()+" before execution", err, admission.ErrTransitionConflict)
	}
	_, _, err := f.l.Finish(a.Attempt.ID, admission.DispositionDeferred)
	wantLedgerReason(t, "deferral as outcome", err, admission.ReasonInvalid)
	_, _, _, _ = f.l.Execute(a.Attempt.ID)
	_, _, err = f.l.Finish(a.Attempt.ID, admission.DispositionNarrowed)
	wantLedgerReason(t, "full block narrowed", err, admission.ReasonInvalid)
	c, done, err := f.l.Finish(a.Attempt.ID, admission.DispositionUnknown)
	if err != nil || c.State != admission.StateUnknown || c.Disposition != admission.DispositionUnknown || done.State != admission.StateUnknown {
		t.Fatalf("unknown: %+v %+v, %v", c, done, err)
	}
	if again, _, againErr := f.l.Finish(a.Attempt.ID, admission.DispositionUnknown); againErr != nil || again.Transitions != c.Transitions {
		t.Fatalf("repeat unknown: %v", againErr)
	}
	_, _, err = f.l.Finish(a.Attempt.ID, admission.DispositionApplied)
	wantLedgerErr(t, "applied after unknown", err, admission.ErrTransitionConflict)
	_, _, _, err = f.l.Reserve(id, time.Time{})
	wantLedgerErr(t, "retry after unknown", err, admission.ErrCandidateTerminal)

	f.nextGeneration()
	id2 := f.queued()
	_, a2, _, _ := f.l.Reserve(id2, ledgerT0.Add(time.Hour))
	_, _, _, _ = f.l.Execute(a2.Attempt.ID)
	if c, _, err := f.l.Finish(a2.Attempt.ID, admission.DispositionApplied); err != nil || c.State != admission.StateVerified || c.Disposition != admission.DispositionApplied {
		t.Fatalf("applied: %+v, %v", c, err)
	}
}

// Time moves only through Tick: a candidate past its age-out, or a retry
// past its absolute expiry, is refused as stale.
func TestAdmissionLedgerRefusesStaleWork(t *testing.T) {
	f := newLedgerFixture(t)
	id := f.queued()
	f.tickAt(ledgerT0.Add(admission.QueueAgeLimit))
	_, _, _, err := f.l.Reserve(id, ledgerT0.Add(24*time.Hour))
	wantLedgerReason(t, "aged out", err, admission.ReasonStale)

	f.nextGeneration()
	f.tickAt(f.wall.Add(time.Minute))
	id2 := f.queued()
	_, a, _, _ := f.l.Reserve(id2, f.wall.Add(10*time.Second))
	f.tickAt(f.wall.Add(10 * time.Second))
	_, _, _, err = f.l.Execute(a.Attempt.ID)
	wantLedgerReason(t, "execute past expiry", err, admission.ReasonStale)
	_, _, _ = f.l.Finish(a.Attempt.ID, admission.DispositionFailed)
	f.tickAt(f.wall.Add(time.Minute))
	_, _, _, err = f.l.Reserve(id2, time.Time{})
	wantLedgerReason(t, "retry past expiry", err, admission.ReasonStale)
}

// A failed transaction leaves the candidate and its attempts as they were.
func TestAdmissionLedgerTransitionsAreAtomic(t *testing.T) {
	f := newLedgerFixture(t)
	id := f.queued()
	before, _ := f.l.Candidate(id)
	f.failNext("reserve")
	if _, _, _, err := f.l.Reserve(id, ledgerT0.Add(time.Hour)); err == nil {
		t.Fatal("injected failure did not fail the reservation")
	}
	after, _ := f.l.Candidate(id)
	if after.State != before.State || after.Transitions != before.Transitions || after.Attempts != 0 {
		t.Fatalf("failed reservation changed the candidate: %+v", after)
	}
	first, _ := admission.NewAttempt(id, 1)
	if _, err := f.l.Attempt(first.ID); err == nil {
		t.Fatal("failed reservation stored an attempt")
	}
	_, a, _, _ := f.l.Reserve(id, ledgerT0.Add(time.Hour))
	_, _, _, _ = f.l.Execute(a.Attempt.ID)
	f.failNext("finish")
	if _, _, err := f.l.Finish(a.Attempt.ID, admission.DispositionApplied); err == nil {
		t.Fatal("injected failure did not fail the outcome")
	}
	if c, _ := f.l.Candidate(id); c.State != admission.StateExecuting {
		t.Fatalf("failed outcome changed the candidate: %s", c.State)
	}
	if got, _ := f.l.Attempt(a.Attempt.ID); got.State != admission.StateExecuting {
		t.Fatalf("failed outcome changed the attempt: %s", got.State)
	}
}

// A stored attempt that is not the candidate's current one cannot change it.
func TestAdmissionLedgerRefusesAStaleAttempt(t *testing.T) {
	f := newLedgerFixture(t)
	id := f.queued()
	_, first, _, _ := f.l.Reserve(id, ledgerT0.Add(time.Hour))
	_, _, _ = f.l.Finish(first.Attempt.ID, admission.DispositionFailed)
	f.tickAt(f.wall.Add(admission.RetryBackoff(1)))
	if _, _, _, err := f.l.Reserve(id, time.Time{}); err != nil {
		t.Fatal(err)
	}
	_, _, _, err := f.l.Execute(first.Attempt.ID)
	wantLedgerErr(t, "stale attempt", err, admission.ErrTransitionConflict)
	// Even a damaged older attempt that reads as reserved cannot act for the
	// candidate's current attempt.
	reopened := first
	reopened.State, reopened.Disposition, reopened.Finished = admission.StateReserved, 0, time.Time{}
	if err = f.db.bolt.Update(func(tx *bolt.Tx) error { return putAttempt(tx, reopened) }); err != nil {
		t.Fatal(err)
	}
	before, _ := f.l.Candidate(id)
	_, _, _, err = f.l.Execute(first.Attempt.ID)
	wantLedgerErr(t, "damaged older attempt", err, admission.ErrCorruptRecord)
	if after, _ := f.l.Candidate(id); after.State != before.State || after.Transitions != before.Transitions {
		t.Fatalf("damaged older attempt changed the candidate: %+v", after)
	}
}

func TestAdmissionLedgerRefusesWorkBeforeItsFirstReading(t *testing.T) {
	db, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	reg, _, _, _ := newLedgerRegistry(t)
	l, err := OpenAdmissionLedger(db, reg)
	if err != nil {
		t.Fatal(err)
	}
	target, _ := admission.CanonicalAddress("192.0.2.10", admission.Caps{})
	episode, _ := admission.ParseEpisodeID("00000000000000000000000000000001")
	req := admission.CandidateRequest{Kind: admission.KindBlockIP, Target: target, Episode: episode, Generation: 1,
		Primary: "ev_00000000000000000000000000000001"}
	_, _, err = l.Enqueue(req)
	wantLedgerReason(t, "enqueue", err, admission.ReasonEngineUnavailable)
	_, _, _, err = l.Reserve("cand_00000000000000000000000000000001", ledgerT0)
	wantLedgerReason(t, "reserve", err, admission.ReasonEngineUnavailable)
}

// Reads do not take the writer mutex and may run while the owner writes.
func TestAdmissionLedgerConcurrentReads(t *testing.T) {
	f := newLedgerFixture(t)
	root := f.published(evidenceSpec{})
	_, id := f.enqueue(f.request("192.0.2.10", root))
	secondRoot := f.published(evidenceSpec{target: "192.0.2.11", cursor: "offset=second"})
	_, secondID := f.enqueue(f.request("192.0.2.11", secondRoot))
	_, a, _, err := f.l.Reserve(secondID, ledgerT0.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	ready := make(chan struct{}, 4)
	stop := make(chan struct{})
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			first := true
			for {
				select {
				case <-stop:
					return
				default:
				}
				if _, err := f.l.Candidate(id); err != nil {
					t.Error(err)
					return
				}
				if !f.l.Inventory().Current(admission.HostOwner()) || f.l.AmbiguousDomains() != 0 {
					t.Error("invalid inventory snapshot")
					return
				}
				if _, err := f.l.Attempt(a.Attempt.ID); err != nil {
					t.Error(err)
					return
				}
				if links, _, err := f.l.Reports(root); err != nil || len(links) > admission.MaxReportLinks {
					t.Errorf("reports: %v", err)
					return
				}
				if _, err := f.l.LoadEvidence(root); err != nil {
					t.Error(err)
					return
				}
				if first {
					ready <- struct{}{}
					first = false
				}
			}
		}()
	}
	defer func() { close(stop); wg.Wait() }()
	for range 4 {
		select {
		case <-ready:
		case <-time.After(10 * time.Second):
			t.Fatal("reader did not start")
		}
	}
	if _, _, _, err := f.l.Execute(a.Attempt.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.l.Finish(a.Attempt.ID, admission.DispositionApplied); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		if err := f.l.LinkReport(root, fmt.Sprintf("%016x", i+1)); err != nil {
			t.Fatal(err)
		}
		f.refresh([]string{"alice", "bob"}, nil)
		if _, err := f.l.Defer(id, []admission.Reason{admission.ReasonCeiling, admission.ReasonSetFull}[i%2]); err != nil {
			t.Fatal(err)
		}
		f.tickAt(f.wall.Add(time.Second))
	}
}

func TestAdmissionLedgerAttemptEvidenceIsFrozen(t *testing.T) {
	f := newLedgerFixture(t)
	primary := f.published(evidenceSpec{})
	req := f.request("192.0.2.10", primary)
	_, id := f.enqueue(req)
	_, a, _, err := f.l.Reserve(id, ledgerT0.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	extra := f.published(evidenceSpec{cursor: "offset=2"})
	req.Support = []admission.EvidenceID{extra}
	for _, running := range []bool{false, true} {
		if running {
			if _, _, _, err := f.l.Execute(a.Attempt.ID); err != nil {
				t.Fatal(err)
			}
		}
		before := f.snapshot()
		_, _, err := f.l.Enqueue(req)
		wantLedgerErr(t, "in-flight root change", err, admission.ErrTransitionConflict)
		if !reflect.DeepEqual(before, f.snapshot()) {
			t.Fatal("in-flight candidate changed")
		}
	}
}

func TestAdmissionLedgerValidatesAttemptHistory(t *testing.T) {
	for _, damage := range []string{"missing", "unknown", "expiry", "finish", "current phase"} {
		t.Run(damage, func(t *testing.T) {
			f := newLedgerFixture(t)
			id := f.queued()
			_, a, _, err := f.l.Reserve(id, ledgerT0.Add(time.Hour))
			if err != nil {
				t.Fatal(err)
			}
			if damage != "current phase" {
				if _, _, err = f.l.Finish(a.Attempt.ID, admission.DispositionFailed); err != nil {
					t.Fatal(err)
				}
				f.tickAt(ledgerT0.Add(time.Second))
				a, err = f.l.Attempt(a.Attempt.ID)
				if err != nil {
					t.Fatal(err)
				}
			}
			if err = f.db.bolt.Update(func(tx *bolt.Tx) error {
				switch damage {
				case "missing":
					return tx.Bucket([]byte(admissionAttemptsBucket)).Delete([]byte(a.Attempt.ID))
				case "unknown":
					a.State, a.Disposition = admission.StateUnknown, admission.DispositionUnknown
				case "expiry":
					a.ExpiresAt = a.ExpiresAt.Add(time.Minute)
				case "finish":
					a.Finished = a.Finished.Add(time.Second)
				case "current phase":
					a.State = admission.StateExecuting
				}
				return putAttempt(tx, a)
			}); err != nil {
				t.Fatal(err)
			}
			before := f.snapshot()
			if _, _, _, err = f.l.Reserve(id, time.Time{}); !isCorrupt(err) {
				t.Fatalf("reserve accepted history: %v", err)
			}
			if !reflect.DeepEqual(before, f.snapshot()) {
				t.Fatal("corrupt history changed")
			}
		})
	}
}

func TestAdmissionLedgerPastOutcomeIsIdempotent(t *testing.T) {
	f := newLedgerFixture(t)
	id := f.queued()
	_, a, _, err := f.l.Reserve(id, ledgerT0.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	_, done, err := f.l.Finish(a.Attempt.ID, admission.DispositionFailed)
	if err != nil {
		t.Fatal(err)
	}
	f.tickAt(ledgerT0.Add(time.Second))
	if _, _, _, err = f.l.Reserve(id, time.Time{}); err != nil {
		t.Fatal(err)
	}
	before := f.snapshot()
	_, again, err := f.l.Finish(a.Attempt.ID, admission.DispositionFailed)
	if err != nil || again != done {
		t.Fatalf("past outcome: %+v %v", again, err)
	}
	if !reflect.DeepEqual(before, f.snapshot()) {
		t.Fatal("past outcome changed records")
	}
	_, _, err = f.l.Finish(a.Attempt.ID, admission.DispositionUnknown)
	wantLedgerErr(t, "changed past outcome", err, admission.ErrTransitionConflict)
}

func TestAdmissionLedgerRemainingTransitionsAreAtomic(t *testing.T) {
	for _, op := range []string{"defer", "terminate", "execute"} {
		f := newLedgerFixture(t)
		id := f.queued()
		var action admission.ActionID
		if op == "execute" {
			_, a, _, err := f.l.Reserve(id, ledgerT0.Add(time.Hour))
			if err != nil {
				t.Fatal(err)
			}
			action = a.Attempt.ID
		}
		before := f.snapshot()
		f.failNext(op)
		var err error
		switch op {
		case "defer":
			_, err = f.l.Defer(id, admission.ReasonCeiling)
		case "terminate":
			_, err = f.l.Terminate(id, admission.ReasonProtected)
		case "execute":
			_, _, _, err = f.l.Execute(action)
		}
		if err == nil {
			t.Fatalf("%s did not fail", op)
		}
		if !reflect.DeepEqual(before, f.snapshot()) {
			t.Fatalf("failed %s changed records", op)
		}
	}
}

func TestAdmissionLedgerRecoverySurvivesDatabaseReopen(t *testing.T) {
	f := newLedgerFixture(t)
	id := f.queued()
	_, a, _, err := f.l.Reserve(id, ledgerT0.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	path := f.db.Path()
	if err = f.db.Close(); err != nil {
		t.Fatal(err)
	}
	db, err := Open(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	l, err := OpenAdmissionLedger(db, f.reg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = l.Tick(admission.ClockReading{Wall: f.wall, BootID: ledgerBoot, SinceBoot: f.since}); err != nil {
		t.Fatal(err)
	}
	_, same, _, err := l.Reserve(id, time.Time{})
	if err != nil || same != a {
		t.Fatalf("recovered reservation: %+v %v", same, err)
	}
	if _, _, _, err := l.Execute(a.Attempt.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := l.Finish(a.Attempt.ID, admission.DispositionUnknown); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := l.Reserve(id, time.Time{}); err != admission.ErrCandidateTerminal {
		t.Fatalf("unknown retried: %v", err)
	}
}

func TestAdmissionLedgerRefusesFutureAttempt(t *testing.T) {
	f := newLedgerFixture(t)
	id := f.queued()
	_, a, _, err := f.l.Reserve(id, ledgerT0.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	a.Attempt, err = admission.NewAttempt(id, 2)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.db.bolt.Update(func(tx *bolt.Tx) error { return putAttempt(tx, a) }); err != nil {
		t.Fatal(err)
	}
	before := f.snapshot()
	if _, _, _, err := f.l.Execute(a.Attempt.ID); !isCorrupt(err) {
		t.Fatalf("future attempt acted: %v", err)
	}
	if !reflect.DeepEqual(before, f.snapshot()) {
		t.Fatal("future attempt changed records")
	}
}

func TestAdmissionLedgerBoundaryReservations(t *testing.T) {
	for _, offset := range []time.Duration{-time.Nanosecond, 0, time.Nanosecond} {
		t.Run(offset.String(), func(t *testing.T) {
			f := newLedgerFixture(t)
			id := f.queued()
			f.tickAt(ledgerT0.Add(admission.QueueAgeLimit + offset))
			_, _, _, err := f.l.Reserve(id, f.wall.Add(time.Hour))
			if offset < 0 {
				if err != nil {
					t.Fatal(err)
				}
			} else {
				wantLedgerReason(t, "age boundary", err, admission.ReasonStale)
			}
		})
	}
	f := newLedgerFixture(t)
	id := f.queued()
	_, a, _, err := f.l.Reserve(id, ledgerT0.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = f.l.Finish(a.Attempt.ID, admission.DispositionFailed); err != nil {
		t.Fatal(err)
	}
	f.tickAt(ledgerT0.Add(time.Second - time.Nanosecond))
	_, _, _, err = f.l.Reserve(id, time.Time{})
	wantLedgerErr(t, "before retry", err, admission.ErrNotReady)
	f.tickAt(ledgerT0.Add(time.Second))
	if _, _, _, err = f.l.Reserve(id, time.Time{}); err != nil {
		t.Fatalf("at retry: %v", err)
	}
}

func TestAdmissionLedgerNarrowedOutcomeAndRetryRestart(t *testing.T) {
	f := newLedgerFixture(t)
	primary := f.published(evidenceSpec{})
	req := f.request("192.0.2.10", primary)
	req.Kind = admission.KindChallenge
	_, id := f.enqueue(req)
	expires := ledgerT0.Add(time.Hour)
	_, first, _, err := f.l.Reserve(id, expires)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = f.l.Finish(first.Attempt.ID, admission.DispositionFailed); err != nil {
		t.Fatal(err)
	}
	l, err := OpenAdmissionLedger(f.db, f.reg)
	if err != nil {
		t.Fatal(err)
	}
	f.l = l
	f.tickAt(f.wall)
	_, _, _, err = l.Reserve(id, time.Time{})
	wantLedgerErr(t, "reopened backoff", err, admission.ErrNotReady)
	f.tickAt(ledgerT0.Add(time.Second))
	_, second, _, err := l.Reserve(id, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if second.Attempt.Prev != first.Attempt.ID || !second.ExpiresAt.Equal(expires) {
		t.Fatalf("retry identity: %+v", second)
	}
	if _, _, _, err = l.Execute(second.Attempt.ID); err != nil {
		t.Fatal(err)
	}
	l, err = OpenAdmissionLedger(f.db, f.reg)
	if err != nil {
		t.Fatal(err)
	}
	f.l = l
	f.tickAt(f.wall)
	_, running, _, err := l.Reserve(id, time.Time{})
	if err != nil || running.State != admission.StateExecuting || running.Attempt != second.Attempt {
		t.Fatalf("executing recovery: %+v %v", running, err)
	}
	c, a, err := l.Finish(second.Attempt.ID, admission.DispositionNarrowed)
	if err != nil || c.State != admission.StateVerified || c.Disposition != admission.DispositionNarrowed || a.Disposition != admission.DispositionNarrowed {
		t.Fatalf("narrowed outcome: %+v %+v %v", c, a, err)
	}
	before := f.snapshot()
	if _, _, err = l.Finish(second.Attempt.ID, admission.DispositionNarrowed); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, f.snapshot()) {
		t.Fatal("repeated narrowed outcome changed records")
	}
}

func TestAdmissionLedgerQueuedMutationsRejectBrokenHistory(t *testing.T) {
	for _, op := range []string{"defer", "terminate", "enqueue"} {
		t.Run(op, func(t *testing.T) {
			f := newLedgerFixture(t)
			id := f.queued()
			_, a, _, err := f.l.Reserve(id, ledgerT0.Add(time.Hour))
			if err != nil {
				t.Fatal(err)
			}
			c, a, err := f.l.Finish(a.Attempt.ID, admission.DispositionFailed)
			if err != nil {
				t.Fatal(err)
			}
			a.State, a.Disposition = admission.StateUnknown, admission.DispositionUnknown
			if err = f.db.bolt.Update(func(tx *bolt.Tx) error { return putAttempt(tx, a) }); err != nil {
				t.Fatal(err)
			}
			before := f.snapshot()
			switch op {
			case "defer":
				_, err = f.l.Defer(id, admission.ReasonCeiling)
			case "terminate":
				_, err = f.l.Terminate(id, admission.ReasonProtected)
			case "enqueue":
				_, _, err = f.l.Enqueue(f.request("192.0.2.10", c.Roots[0]))
			}
			if !isCorrupt(err) {
				t.Fatalf("%s accepted broken history: %v", op, err)
			}
			if !reflect.DeepEqual(before, f.snapshot()) {
				t.Fatal("broken history changed")
			}
		})
	}
}

// A readable attempt is not admissible history if it was reserved after
// leaving the queue. Recovery must enforce the same boundary as Reserve.
func TestAdmissionLedgerRejectsReservationsPastQueueDeadline(t *testing.T) {
	for _, seq := range []uint32{1, 2} {
		for _, offset := range []time.Duration{0, time.Nanosecond} {
			for _, op := range []string{"reserve", "execute", "finish", "defer", "terminate", "enqueue"} {
				t.Run(fmt.Sprintf("attempt=%d/late=%s/%s", seq, offset, op), func(t *testing.T) {
					f := newLedgerFixture(t)
					id := f.queued()
					var c admission.Candidate
					var a admission.AttemptRecord
					for n := uint32(1); n <= seq; n++ {
						f.tickAt(f.wall.Add(time.Minute))
						var err error
						c, a, _, err = f.l.Reserve(id, ledgerT0.Add(24*time.Hour))
						if err != nil {
							t.Fatal(err)
						}
						if n < seq || op == "defer" || op == "terminate" || op == "enqueue" {
							c, a, err = f.l.Finish(a.Attempt.ID, admission.DispositionFailed)
							if err != nil {
								t.Fatal(err)
							}
						}
					}
					c.AgeOut = a.Reserved.Add(-offset)
					if err := f.db.bolt.Update(func(tx *bolt.Tx) error { return putCandidate(tx, c) }); err != nil {
						t.Fatal(err)
					}
					before := f.snapshot()
					var err error
					switch op {
					case "reserve":
						_, _, _, err = f.l.Reserve(id, time.Time{})
					case "execute":
						_, _, _, err = f.l.Execute(a.Attempt.ID)
					case "finish":
						_, _, err = f.l.Finish(a.Attempt.ID, admission.DispositionFailed)
					case "defer":
						_, err = f.l.Defer(id, admission.ReasonCeiling)
					case "terminate":
						_, err = f.l.Terminate(id, admission.ReasonStale)
					case "enqueue":
						_, _, err = f.l.Enqueue(f.request("192.0.2.10", c.Roots[0]))
					}
					wantLedgerErr(t, "reservation outside queue lifetime", err, admission.ErrCorruptRecord)
					if !reflect.DeepEqual(before, f.snapshot()) {
						t.Fatal("invalid reservation history changed records")
					}
				})
			}
		}
	}
}

// A reopened ledger, or one whose last reading was refused, keeps its stored
// high-water mark but admits and dispatches nothing until it records a new
// reading: after a restart the stored time can be hours old, and old evidence
// would read as fresh. Recording the outcome of running work needs only the
// stored time.
func TestAdmissionLedgerAdmitsOnlyAfterACurrentReading(t *testing.T) {
	f := newLedgerFixture(t)
	id := f.queued()
	_, a, _, err := f.l.Reserve(id, ledgerT0.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	other := f.published(evidenceSpec{target: "192.0.2.11", cursor: "offset=other"})
	refused := func(when string) {
		t.Helper()
		before := f.snapshot()
		_, _, gateErr := f.l.Enqueue(f.request("192.0.2.11", other))
		wantLedgerReason(t, when+": enqueue", gateErr, admission.ReasonEngineUnavailable)
		_, _, _, gateErr = f.l.Reserve(id, time.Time{})
		wantLedgerReason(t, when+": reserve", gateErr, admission.ReasonEngineUnavailable)
		_, _, _, gateErr = f.l.Execute(a.Attempt.ID)
		wantLedgerReason(t, when+": execute", gateErr, admission.ReasonEngineUnavailable)
		if !reflect.DeepEqual(before, f.snapshot()) {
			t.Fatalf("%s: refused calls changed records", when)
		}
	}
	if f.l, err = OpenAdmissionLedger(f.db, f.reg); err != nil {
		t.Fatal(err)
	}
	refused("reopened")
	f.tickAt(f.wall.Add(time.Minute))
	if _, _, _, err = f.l.Execute(a.Attempt.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = f.l.Tick(admission.ClockReading{Wall: f.wall.Add(time.Minute), SinceBoot: f.since + time.Minute}); err == nil {
		t.Fatal("reading without a boot ID accepted")
	}
	refused("after a refused reading")
	if c, _, finishErr := f.l.Finish(a.Attempt.ID, admission.DispositionApplied); finishErr != nil || c.State != admission.StateVerified {
		t.Fatalf("outcome of running work: %+v, %v", c, finishErr)
	}
	f.tickAt(f.wall.Add(time.Minute))
	if _, created, enqueueErr := f.l.Enqueue(f.request("192.0.2.11", other)); enqueueErr != nil || !created {
		t.Fatalf("enqueue after a current reading: %v, %v", created, enqueueErr)
	}
}

// Only the call that makes a step grants it. Reserve on a reserved or running
// candidate and Execute on a running attempt are readbacks: the same records
// with the grant flag false, so recovery never mistakes an uncertain attempt
// for permission to dispatch it again.
func TestAdmissionLedgerReadbackGrantsNothing(t *testing.T) {
	f := newLedgerFixture(t)
	id := f.queued()
	_, a, granted, err := f.l.Reserve(id, ledgerT0.Add(time.Hour))
	if err != nil || !granted {
		t.Fatalf("first reservation: granted %v, %v", granted, err)
	}
	if _, again, readGranted, readErr := f.l.Reserve(id, time.Time{}); readErr != nil || readGranted || again != a {
		t.Fatalf("reserved readback: %+v granted %v, %v", again, readGranted, readErr)
	}
	_, running, started, err := f.l.Execute(a.Attempt.ID)
	if err != nil || !started || running.State != admission.StateExecuting {
		t.Fatalf("first execute: %+v started %v, %v", running, started, err)
	}
	if _, again, readStarted, readErr := f.l.Execute(a.Attempt.ID); readErr != nil || readStarted || again != running {
		t.Fatalf("running readback: %+v started %v, %v", again, readStarted, readErr)
	}
	if _, again, readGranted, readErr := f.l.Reserve(id, time.Time{}); readErr != nil || readGranted || again != running {
		t.Fatalf("running reservation readback: %+v granted %v, %v", again, readGranted, readErr)
	}
	if _, _, err = f.l.Finish(a.Attempt.ID, admission.DispositionFailed); err != nil {
		t.Fatal(err)
	}
	f.tickAt(f.wall.Add(admission.RetryBackoff(1)))
	if _, retry, retryGranted, retryErr := f.l.Reserve(id, time.Time{}); retryErr != nil || !retryGranted || retry.Attempt.Seq != 2 {
		t.Fatalf("retry after a proven failure: %+v granted %v, %v", retry, retryGranted, retryErr)
	}
}
