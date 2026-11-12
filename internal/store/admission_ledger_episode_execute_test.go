package store

import (
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
)

// A verified episode ends when its block's element does, on both clocks,
// from the reading the block ran at: a forward wall step between Execute
// and Finish cannot shorten it. The reading is kept only until
// the outcome.
func TestAdmissionLedgerVerifiedEpisodeEndsFromTheExecuteReading(t *testing.T) {
	f := newLedgerFixture(t)
	f.begin()
	f.tickAt(f.wall.Add(time.Minute))
	id := f.arrive(f.arrival(evidenceSpec{cursor: "offset=1"}))[0].Candidate
	expiry := f.wall.Add(20 * time.Minute)
	_, a, _, err := f.l.Reserve(id, admission.LaneGeneral, expiry)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err = f.l.Execute(a.Attempt.ID); err != nil {
		t.Fatal(err)
	}
	executed := f.ceilingState().Elapsed
	f.stepWall(10*time.Minute, time.Second)
	f.tickAt(f.wall.Add(time.Second))
	// Asking again for a batch that already runs changes nothing, not
	// even the reading it ran at.
	if _, _, granted, execErr := f.l.Execute(a.Attempt.ID); execErr != nil || granted {
		t.Fatalf("a running batch again: granted %v, %v", granted, execErr)
	}
	if _, _, err = f.l.Finish(a.Attempt.ID, admission.DispositionApplied); err != nil {
		t.Fatal(err)
	}
	row, _ := f.episodeAt("192.0.2.10")
	if !row.Verified.Equal(expiry) || row.EndElapsed != executed+20*time.Minute {
		t.Fatalf("verified row %+v; want the block's 20 minutes from the execute reading (elapsed %v)", row, executed)
	}
	if n := len(f.l.executed); n != 0 {
		t.Fatalf("%d execute readings kept after the outcome", n)
	}
}

// An outcome other than a verified block also drops the execute reading,
// an existing effect's included.
func TestAdmissionLedgerOutcomeDropsTheExecuteReading(t *testing.T) {
	for _, d := range []admission.Disposition{admission.DispositionFailed, admission.DispositionUnknown, admission.DispositionObserve} {
		f := newLedgerFixture(t)
		f.begin()
		id := f.arrive(f.arrival(evidenceSpec{cursor: "offset=1"}))[0].Candidate
		_, a, _, err := f.l.Reserve(id, admission.LaneGeneral, f.wall.Add(time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		if _, _, _, err = f.l.Execute(a.Attempt.ID); err != nil {
			t.Fatal(err)
		}
		if n := len(f.l.executed); n != 1 {
			t.Fatalf("%s: %d execute readings after Execute, want 1", d, n)
		}
		if d == admission.DispositionObserve {
			_, _, err = f.l.FinishExisting(a.Attempt.ID, testLink("eff_", f.wall.Add(time.Hour)))
		} else {
			_, _, err = f.l.Finish(a.Attempt.ID, d)
		}
		if err != nil {
			t.Fatal(err)
		}
		if n := len(f.l.executed); n != 0 {
			t.Fatalf("%s: %d execute readings kept after the outcome", d, n)
		}
	}
}

// Only a committed execution records a reading. Failed writes preserve
// existing readings, and one member's outcome cannot erase its peers.
func TestAdmissionLedgerExecuteReadingLifecycle(t *testing.T) {
	f := newLedgerFixture(t)
	f.begin()
	var ids []admission.ActionID
	for _, ip := range []string{"192.0.2.10", "192.0.2.11"} {
		res := f.arrive(f.arrival(evidenceSpec{target: ip, cursor: ip}))[0]
		_, a, _, err := f.l.Reserve(res.Candidate, admission.LaneGeneral, f.wall.Add(time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, a.Attempt.ID)
	}
	if len(f.l.executed) != 0 {
		t.Fatal("reservation recorded an execute reading")
	}
	f.failNext("execute")
	if _, _, err := f.l.ExecuteBatch(ids); err == nil || len(f.l.executed) != 0 {
		t.Fatalf("failed execution recorded a reading: %v %+v", err, f.l.executed)
	}
	if _, granted, err := f.l.ExecuteBatch(ids); err != nil || !granted || len(f.l.executed) != 2 {
		t.Fatalf("execution readings: %v %v %+v", granted, err, f.l.executed)
	}
	first := f.l.executed[ids[0]]
	if got := f.l.executed[ids[1]]; got != first {
		t.Fatalf("batch used different readings: %+v %+v", first, got)
	}
	f.failNext("finish")
	if _, _, err := f.l.Finish(ids[0], admission.DispositionApplied); err == nil || len(f.l.executed) != 2 || f.l.executed[ids[0]] != first {
		t.Fatalf("failed outcome lost its reading: %v %+v", err, f.l.executed)
	}
	if _, _, err := f.l.Finish(ids[0], admission.DispositionApplied); err != nil {
		t.Fatal(err)
	}
	if _, exists := f.l.executed[ids[0]]; exists || len(f.l.executed) != 1 || f.l.executed[ids[1]] != first {
		t.Fatalf("one outcome changed another reading: %+v", f.l.executed)
	}
	if _, _, err := f.l.Finish(ids[1], admission.DispositionUnknown); err != nil || len(f.l.executed) != 0 {
		t.Fatalf("unknown outcome retained readings: %v %+v", err, f.l.executed)
	}
}

// A missing in-memory execute reading falls back to the outcome reading;
// it must not turn into the zero clock or a refused verified outcome.
func TestAdmissionLedgerExecuteReadingFallback(t *testing.T) {
	f := newLedgerFixture(t)
	f.begin()
	id := f.arrive(f.arrival(evidenceSpec{cursor: "fallback"}))[0].Candidate
	expiry := f.wall.Add(time.Hour)
	_, a, _, err := f.l.Reserve(id, admission.LaneGeneral, expiry)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err = f.l.Execute(a.Attempt.ID); err != nil {
		t.Fatal(err)
	}
	delete(f.l.executed, a.Attempt.ID)
	f.stepWall(10*time.Minute, time.Second)
	f.tickAt(f.wall.Add(time.Second))
	want := f.ceilingState().Elapsed + expiry.Sub(f.wall)
	if _, _, err = f.l.Finish(a.Attempt.ID, admission.DispositionApplied); err != nil {
		t.Fatal(err)
	}
	row, _ := f.episodeAt("192.0.2.10")
	if !row.Verified.Equal(expiry) || row.EndElapsed != want || len(f.l.executed) != 0 {
		t.Fatalf("fallback boundary %+v, want elapsed %v and no reading", row, want)
	}
}

// A reopened handle can execute an inherited reservation before settling
// it. Settlement records its unknown outcome and releases its reading.
func TestAdmissionLedgerSettlementDropsExecuteReadings(t *testing.T) {
	f := newLedgerFixture(t)
	_, a := f.admitted(time.Hour)
	var err error
	if f.l, err = OpenAdmissionLedger(f.db, f.reg); err != nil {
		t.Fatal(err)
	}
	f.tickAt(f.wall.Add(time.Second))
	if _, _, granted, err := f.l.Execute(a.Attempt.ID); err != nil || !granted {
		t.Fatalf("inherited execution: %v %v", granted, err)
	}
	if len(f.l.executed) != 1 {
		t.Fatal("execution did not retain its reading")
	}
	f.failNext("settle")
	if _, _, err := f.l.Settle(); err == nil || len(f.l.executed) != 1 {
		t.Fatalf("failed settlement lost its reading: %v", err)
	}
	if failed, unknown, err := f.l.Settle(); err != nil || failed != 0 || unknown != 1 {
		t.Fatalf("settlement: %d failed, %d unknown, %v", failed, unknown, err)
	}
	if len(f.l.executed) != 0 {
		t.Fatal("settlement kept a completed attempt's execute reading")
	}
}
