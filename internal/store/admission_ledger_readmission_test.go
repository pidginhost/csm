package store

import (
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	bolt "go.etcd.io/bbolt"
)

// verifiedArrival places an arrival at target, then reserves, runs and
// verifies its block for ttl.
func (f *ledgerFixture) verifiedArrival(target, cursor string, severity admission.Severity, ttl time.Duration) admission.AttemptRecord {
	f.t.Helper()
	res := f.arrive(f.arrival(evidenceSpec{target: target, cursor: cursor, severity: severity}))[0]
	if res.Err != nil {
		f.t.Fatal(res.Err)
	}
	_, a, _, err := f.l.Reserve(res.Candidate, admission.LaneGeneral, f.wall.Add(ttl))
	if err != nil {
		f.t.Fatal(err)
	}
	if _, _, _, err = f.l.Execute(a.Attempt.ID); err != nil {
		f.t.Fatal(err)
	}
	if _, _, err = f.l.Finish(a.Attempt.ID, admission.DispositionApplied); err != nil {
		f.t.Fatal(err)
	}
	return a
}

// goneArrival is a live ledger whose verified block at 192.0.2.10 two
// firewall answers missed, and the reading of the first miss.
func goneArrival(t *testing.T) (*ledgerFixture, admission.AttemptRecord, time.Time) {
	t.Helper()
	f := liveLedgerFixture(t)
	f.begin()
	a := f.verifiedArrival("192.0.2.10", "offset=1", admission.SeverityHigh, time.Hour)
	asked, err := f.l.HeldEffects(10)
	if err != nil || len(asked) != 1 {
		t.Fatalf("held %+v %v", asked, err)
	}
	f.observeHeld(asked, false)
	gone := f.wall
	if n := f.observeHeld(asked, false); n != 1 {
		t.Fatalf("two misses marked %d", n)
	}
	return f, a, gone
}

// A fresh attack on a block that left before its episode's end is the
// same episode (spec 5.2): a charged new generation of the same kind,
// queued, while the episode keeps its boundary and earns no rotation.
func TestAdmissionLedgerReadmitsAGoneBlockInItsEpisode(t *testing.T) {
	f, a, _ := goneArrival(t)
	first := f.candidateOf(a.Attempt.Candidate)
	before, _ := f.episodeAt("192.0.2.10")
	f.tickAt(f.wall.Add(time.Minute))
	res := f.arrive(f.arrival(evidenceSpec{cursor: "offset=2"}))[0]
	if res.Err != nil || !res.Created {
		t.Fatalf("re-admission arrival = %+v", res)
	}
	c := f.candidateOf(res.Candidate)
	if c.Key.Episode != first.Key.Episode || c.Key.Generation != first.Key.Generation+1 || c.State != admission.StateQueued {
		t.Fatalf("re-admission %+v, want generation %d of episode %v", c, first.Key.Generation+1, first.Key.Episode)
	}
	row, _ := f.episodeAt("192.0.2.10")
	line, _ := row.Line(admission.KindBlockIP)
	if !row.Verified.Equal(before.Verified) || row.EndElapsed != before.EndElapsed || line.Candidate != res.Candidate || line.Generation != c.Key.Generation {
		t.Fatalf("row after re-admission %+v, before %+v", row, before)
	}
	if fresh, err := f.l.Fresh(c); err != nil || fresh {
		t.Fatalf("a re-admission is fresh for rotation: %v %v", fresh, err)
	}
	used := f.ceilingState().General.Used
	_, second, granted, err := f.l.Reserve(res.Candidate, admission.LaneGeneral, before.Verified.Add(-time.Minute))
	if err != nil || !granted || second.Attempt.ID == a.Attempt.ID || f.ceilingState().General.Used != used+1 {
		t.Fatalf("re-admission was not newly charged: %+v %v %v", second, granted, err)
	}
	if _, _, _, err = f.l.Execute(second.Attempt.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err = f.l.Finish(second.Attempt.ID, admission.DispositionApplied); err != nil {
		t.Fatal(err)
	}
	after, _ := f.episodeAt("192.0.2.10")
	if !after.Verified.Equal(before.Verified) || after.EndElapsed != before.EndElapsed {
		t.Fatalf("verified re-admission moved the boundary: before %+v after %+v", before, after)
	}
}

// Until the ledger marks it gone, a verified block answers its episode.
func TestAdmissionLedgerAnswersUntilTheGoneMark(t *testing.T) {
	f := liveLedgerFixture(t)
	f.begin()
	f.verifiedArrival("192.0.2.10", "offset=1", admission.SeverityHigh, time.Hour)
	asked, _ := f.l.HeldEffects(10)
	f.observeHeld(asked, false)
	f.tickAt(f.wall.Add(time.Minute))
	wantLedgerReason(t, "after one miss", f.arrive(f.arrival(evidenceSpec{cursor: "offset=2"}))[0].Err, admission.ReasonExistingEffect)
}

// Only evidence observed after the removal can re-admit (T4, spec 5.13):
// an observation from before it is answered, and a fresh observation
// supported by a root from before it is stale. Neither queues anything.
func TestAdmissionLedgerReadmissionNeedsEvidenceAfterTheRemoval(t *testing.T) {
	f, _, gone := goneArrival(t)
	f.tickAt(f.wall.Add(time.Minute))
	early := f.wall.Sub(gone) + time.Second
	wantLedgerReason(t, "an observation from before the removal", f.arrive(f.arrival(evidenceSpec{cursor: "offset=2", age: early}))[0].Err, admission.ReasonExistingEffect)
	old := f.published(evidenceSpec{cursor: "offset=3", age: early})
	e := f.mint(evidenceSpec{cursor: "offset=4"})
	req := f.request("192.0.2.10", e.ID(), old)
	req.Episode, req.Generation = admission.EpisodeID{}, 0
	res := f.arrive(admission.Arrival{Request: req, Evidence: e})[0]
	wantLedgerReason(t, "support from before the removal", res.Err, admission.ReasonStale)
	if res.Created {
		t.Fatalf("stale support queued %+v", res)
	}
	row, _ := f.episodeAt("192.0.2.10")
	if line, _ := row.Line(admission.KindBlockIP); line.Generation != 1 {
		t.Fatalf("a refused arrival moved the line: %+v", line)
	}
}

// A verified eviction is a removal the ledger proved: the evicted block's
// return before its episode's end is re-admitted.
func TestAdmissionLedgerReadmitsAnEvictedBlock(t *testing.T) {
	f := liveLedgerFixture(t)
	f.begin()
	f.l.SetOccupants(&fullGeneral)
	low := f.verifiedArrival("192.0.2.10", "offset=1", admission.SeverityWarning, time.Hour)
	a := f.evicting("192.0.2.11", low)
	if _, _, _, err := f.l.Execute(a.Attempt.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.l.Finish(a.Attempt.ID, admission.DispositionApplied); err != nil {
		t.Fatal(err)
	}
	f.tickAt(f.wall.Add(time.Minute))
	res := f.arrive(f.arrival(evidenceSpec{cursor: "offset=2", severity: admission.SeverityWarning}))[0]
	if c := f.candidateOf(res.Candidate); res.Err != nil || !res.Created || c.Key.Generation != 2 {
		t.Fatalf("return after eviction = %+v %+v", res, c.Key)
	}
}

// Re-admission never outlives the block's original expiry (spec 5.4):
// after a reboot leaves the episode open on elapsed time past that end,
// a return is answered until the episode ends on both clocks, even while
// the block's record, which a lease lead keeps past the end, says gone.
func TestAdmissionLedgerNoReadmissionAfterTheVerifiedEnd(t *testing.T) {
	f := liveLedgerFixture(t)
	f.begin()
	res := f.arrive(f.arrival(evidenceSpec{cursor: "offset=1", severity: admission.SeverityHigh}))[0]
	_, a, _, err := f.l.Reserve(res.Candidate, admission.LaneGeneral, f.wall.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err = f.l.Execute(a.Attempt.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err = f.l.FinishOnLease(a.Attempt.ID, admission.DispositionApplied, 30*time.Minute); err != nil {
		t.Fatal(err)
	}
	asked, _ := f.l.HeldEffects(10)
	f.observeHeld(asked, false)
	if n := f.observeHeld(asked, false); n != 1 {
		t.Fatalf("two misses marked %d", n)
	}
	row, _ := f.episodeAt("192.0.2.10")
	if f.l, err = OpenAdmissionLedger(f.db, f.reg); err != nil {
		t.Fatal(err)
	}
	f.wall, f.since = row.Verified, time.Minute
	if tick, tickErr := f.l.Tick(admission.ClockReading{Wall: f.wall, BootID: ledgerRebootID, SinceBoot: f.since}); tickErr != nil || tick.Degraded {
		t.Fatalf("tick = %+v, %v", tick, tickErr)
	}
	f.begin()
	if rec, found := f.effectOf(a); !found || rec.Gone.IsZero() || f.ceilingState().Elapsed >= row.EndElapsed {
		t.Fatalf("setup: record %+v (found %v), ceiling %v, end %v", rec, found, f.ceilingState().Elapsed, row.EndElapsed)
	}
	wantLedgerReason(t, "at the verified end", f.arrive(f.arrival(evidenceSpec{cursor: "offset=2"}))[0].Err, admission.ReasonExistingEffect)
	f.tickAt(f.wall.Add(time.Minute))
	wantLedgerReason(t, "after the verified end", f.arrive(f.arrival(evidenceSpec{cursor: "offset=3"}))[0].Err, admission.ReasonExistingEffect)
}

// The removal gate survives coalescing and a refused later generation.
// Every supplied root must be newer than the last verified removal.
func TestAdmissionLedgerReadmissionKeepsItsEvidenceGate(t *testing.T) {
	for _, ended := range []bool{false, true} {
		f, _, gone := goneArrival(t)
		f.tickAt(f.wall.Add(time.Minute))
		res := f.arrive(f.arrival(evidenceSpec{cursor: "fresh-1"}))[0]
		if res.Err != nil || !res.Created {
			t.Fatalf("initial return: %+v", res)
		}
		before := f.candidateOf(res.Candidate)
		if ended {
			if _, err := f.l.Terminate(res.Candidate, admission.ReasonStale); err != nil {
				t.Fatal(err)
			}
		}
		f.tickAt(f.wall.Add(time.Second))
		old := f.published(evidenceSpec{cursor: "old-support", age: f.wall.Sub(gone)})
		fresh := f.published(evidenceSpec{cursor: "fresh-support"})
		e := f.mint(evidenceSpec{cursor: "fresh-2"})
		req := f.request("192.0.2.10", e.ID(), fresh, old)
		req.Episode, req.Generation = admission.EpisodeID{}, 0
		got := f.arrive(admission.Arrival{Request: req, Evidence: e})[0]
		wantLedgerReason(t, "stale support after the line changed", got.Err, admission.ReasonStale)
		if got.Created || len(f.candidateOf(res.Candidate).Roots) != len(before.Roots) {
			t.Fatalf("stale support changed the candidate: %+v", got)
		}
		// New roots still qualify, including support observed after Gone
		// but before this generation was first queued.
		support := f.published(evidenceSpec{cursor: "post-gone", age: f.wall.Sub(gone.Add(time.Second))})
		e = f.mint(evidenceSpec{cursor: "fresh-3"})
		req = f.request("192.0.2.10", e.ID(), support)
		req.Episode, req.Generation = admission.EpisodeID{}, 0
		got = f.arrive(admission.Arrival{Request: req, Evidence: e})[0]
		if got.Err != nil || got.Created != ended {
			t.Fatalf("fresh support after the line changed: %+v", got)
		}
		generation := before.Key.Generation
		if ended {
			generation++
		}
		if c := f.candidateOf(got.Candidate); c.Key.Episode != before.Key.Episode || c.Key.Generation != generation {
			t.Fatalf("return changed the episode or generation: %+v", c.Key)
		}
	}
}

// Equality is not post-removal evidence; disabling the live ledger keeps
// even a stored gone record from authorizing a re-admission.
func TestAdmissionLedgerReadmissionStrictBoundaries(t *testing.T) {
	for _, live := range []bool{false, true} {
		f, _, gone := goneArrival(t)
		f.l.live = live
		f.tickAt(f.wall.Add(time.Minute))
		age := time.Duration(0)
		if live {
			age = f.wall.Sub(gone)
		}
		res := f.arrive(f.arrival(evidenceSpec{cursor: "at-gone", age: age}))[0]
		wantLedgerReason(t, "no live post-removal observation", res.Err, admission.ReasonExistingEffect)
		if res.Created {
			t.Fatalf("boundary observation queued: %+v", res)
		}
	}
}

// Retiring a refused, unattempted return must not erase the verified
// episode or turn its missing line into permission for another block.
// Once both ends pass, the predecessor's retirement collects the row.
func TestAdmissionLedgerReadmissionRetirementKeepsTheBoundary(t *testing.T) {
	f, first, _ := goneArrival(t)
	original := f.candidateOf(first.Attempt.Candidate)
	before, _ := f.episodeAt("192.0.2.10")
	f.tickAt(f.wall.Add(time.Minute))
	res := f.arrive(f.arrival(evidenceSpec{cursor: "return"}))[0]
	if res.Err != nil || !res.Created {
		t.Fatalf("initial return: %+v", res)
	}
	if _, err := f.l.Terminate(res.Candidate, admission.ReasonStale); err != nil {
		t.Fatal(err)
	}
	forget := func(id admission.CandidateID, c admission.Candidate) {
		t.Helper()
		if forgetErr := f.db.bolt.Update(func(tx *bolt.Tx) error {
			q, openErr := f.l.openQueue(tx, f.wall)
			if openErr != nil {
				return openErr
			}
			return q.forgetLine(id, c)
		}); forgetErr != nil {
			t.Fatal(forgetErr)
		}
	}
	forget(res.Candidate, f.candidateOf(res.Candidate))
	row, found := f.episodeAt("192.0.2.10")
	line, _ := row.Line(admission.KindBlockIP)
	if !found || row.ID != before.ID || !row.Verified.Equal(before.Verified) || row.EndElapsed != before.EndElapsed || line.Candidate != "" || !line.Answered {
		t.Fatalf("forgetting the return lost its boundary: %+v, found %v", row, found)
	}
	f.tickAt(f.wall.Add(time.Second))
	wantLedgerReason(t, "missing return history", f.arrive(f.arrival(evidenceSpec{cursor: "after-forget"}))[0].Err, admission.ReasonExistingEffect)
	var err error
	if f.l, err = OpenAdmissionLedger(f.db, f.reg); err != nil {
		t.Fatal(err)
	}
	f.wall, f.since = before.Verified, time.Minute
	if _, err = f.l.Tick(admission.ClockReading{Wall: f.wall, BootID: ledgerRebootID, SinceBoot: f.since}); err != nil {
		t.Fatal(err)
	}
	forget(first.Attempt.Candidate, original)
	if row, found = f.episodeAt("192.0.2.10"); !found || row.EndElapsed != before.EndElapsed {
		t.Fatalf("wall expiry alone discarded retained proof: %+v", row)
	}
	f.ackAll()
	f.wall, f.since = f.wall.Add(admission.HistoryTarget+time.Hour), f.since+time.Hour
	if _, err = f.l.Tick(admission.ClockReading{Wall: f.wall, BootID: ledgerRebootID, SinceBoot: f.since}); err != nil {
		t.Fatal(err)
	}
	if _, found = f.historyEntry(first.Attempt.Candidate); found {
		t.Fatal("expired predecessor history was not retired")
	}
	if row, found = f.episodeAt("192.0.2.10"); found {
		t.Fatalf("expired unreferenced episode was retained: %+v", row)
	}
}
