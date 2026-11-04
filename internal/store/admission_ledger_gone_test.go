package store

import (
	"reflect"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	bolt "go.etcd.io/bbolt"
)

// heldOf is the entry HeldEffects lists for verified attempt a at target.
func (f *ledgerFixture) heldOf(a admission.AttemptRecord, target string) HeldEffect {
	f.t.Helper()
	return HeldEffect{Action: a.Attempt.ID, Target: f.target(target), ExpiresAt: a.ExpiresAt}
}

// observeHeld answers asked with held at a reading one minute later and
// returns how many blocks the ledger marked gone.
func (f *ledgerFixture) observeHeld(asked []HeldEffect, held ...bool) int {
	f.t.Helper()
	f.tickAt(f.wall.Add(time.Minute))
	n, err := markedCount(f.l.ObserveHeld(asked, held))
	if err != nil {
		f.t.Fatal(err)
	}
	return n
}

// The ledger lists the verified blocks whose records hold a slot, soonest
// expiry first and at most limit: not a pending reservation, not a victim
// a pending block claimed, and nothing before the live start.
func TestAdmissionLedgerListsTheBlocksItCountsAsHeld(t *testing.T) {
	if got, err := newLedgerFixture(t).l.HeldEffects(10); err != nil || len(got) != 0 {
		t.Fatalf("before the live start: %+v %v", got, err)
	}
	f := liveLedgerFixture(t)
	later := f.verifiedWith("192.0.2.10", admission.SeverityWarning, 2*time.Hour)
	sooner := f.verifiedWith("192.0.2.11", admission.SeverityWarning, time.Hour)
	if _, _, _, err := f.l.Reserve(f.queuedWith("192.0.2.12", admission.SeverityWarning), admission.LaneGeneral, f.wall.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	got, err := f.l.HeldEffects(10)
	if want := []HeldEffect{f.heldOf(sooner, "192.0.2.11"), f.heldOf(later, "192.0.2.10")}; err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("held %+v %v, want %+v", got, err, want)
	}
	if got, err = f.l.HeldEffects(1); err != nil || !reflect.DeepEqual(got, []HeldEffect{f.heldOf(sooner, "192.0.2.11")}) {
		t.Fatalf("limit 1: %+v %v", got, err)
	}
	_, err = f.l.HeldEffects(0)
	wantLedgerReason(t, "limit 0", err, admission.ReasonInvalid)
	f.l.SetOccupants(&admission.SetOccupancy{Limit: 5, Unclaimed: 1})
	f.evicting("192.0.2.13", sooner)
	if got, err = f.l.HeldEffects(10); err != nil || !reflect.DeepEqual(got, []HeldEffect{f.heldOf(later, "192.0.2.10")}) {
		t.Fatalf("with a claimed victim: %+v %v", got, err)
	}
}

// A block missed by two consecutive answers is gone: its record keeps
// everything it recorded, notes the reading of the first miss, gives up
// its slot and stays listed no longer. The first gone record raises the
// schema.
func TestAdmissionLedgerTwoMissesMarkABlockGone(t *testing.T) {
	f := liveLedgerFixture(t)
	a := f.verifiedWith("192.0.2.10", admission.SeverityWarning, time.Hour)
	b := f.verifiedWith("192.0.2.11", admission.SeverityWarning, 2*time.Hour)
	asked, err := f.l.HeldEffects(10)
	if err != nil || len(asked) != 2 {
		t.Fatalf("held %+v %v", asked, err)
	}
	before, _ := f.effectOf(a)
	if n := f.observeHeld(asked, false, true); n != 0 {
		t.Fatalf("one miss marked %d gone", n)
	}
	firstMiss := f.wall
	if rec, _ := f.effectOf(a); rec != before {
		t.Fatalf("one miss changed the record: %+v", rec)
	}
	if _, _, schema := f.effectRecords(); schema >= admissionSchemaEffectGone {
		t.Fatalf("schema %d after one miss", schema)
	}
	if n := f.observeHeld(asked, false, true); n != 1 {
		t.Fatalf("two misses marked %d gone, want 1", n)
	}
	rec, _ := f.effectOf(a)
	want := before
	want.Gone = firstMiss
	if rec != want || rec.Holds() {
		t.Fatalf("gone record %+v, want %+v", rec, want)
	}
	if kept, _ := f.effectOf(b); !kept.Gone.IsZero() || !kept.Holds() {
		t.Fatalf("a held block changed: %+v", kept)
	}
	records, tally, schema := f.effectRecords()
	if len(records) != 2 || tally != (admission.EffectTally{General: 1}) || schema != admissionSchemaEffectGone {
		t.Fatalf("records %d, tally %+v, schema %d", len(records), tally, schema)
	}
	if got, _ := f.l.HeldEffects(10); !reflect.DeepEqual(got, []HeldEffect{f.heldOf(b, "192.0.2.11")}) {
		t.Fatalf("still listed: %+v", got)
	}
	if s := f.l.Status().Effects; s.General != 1 || s.Error != "" {
		t.Fatalf("status %+v, want one held slot", s)
	}
	if _, err := OpenAdmissionLedger(f.db, f.reg); err != nil {
		t.Fatalf("reopening with a gone record: %v", err)
	}
}

// A held answer between two misses starts the count again, and the miss
// that starts it is the one a gone record notes.
func TestAdmissionLedgerAHeldAnswerResetsTheMisses(t *testing.T) {
	f := liveLedgerFixture(t)
	a := f.verifiedWith("192.0.2.10", admission.SeverityWarning, time.Hour)
	asked, _ := f.l.HeldEffects(10)
	for i, held := range []bool{false, true, false} {
		if n := f.observeHeld(asked, held); n != 0 {
			t.Fatalf("answer %d marked %d gone", i, n)
		}
	}
	restart := f.wall
	if n := f.observeHeld(asked, false); n != 1 {
		t.Fatalf("the second consecutive miss marked %d gone", n)
	}
	if rec, _ := f.effectOf(a); !rec.Gone.Equal(restart) {
		t.Fatalf("gone at %v, want the miss after the held answer, %v", rec.Gone, restart)
	}
	// A block the ledger no longer lists is forgotten, so a later list
	// that names it again needs two new misses.
	g := liveLedgerFixture(t)
	c := g.verifiedWith("192.0.2.10", admission.SeverityWarning, time.Hour)
	d := g.verifiedWith("192.0.2.11", admission.SeverityWarning, time.Hour)
	both, _ := g.l.HeldEffects(10)
	g.observeHeld(both, false, false)
	if n := g.observeHeld([]HeldEffect{g.heldOf(c, "192.0.2.10")}, true); n != 0 {
		t.Fatalf("an unlisted block was marked: %d", n)
	}
	if n := g.observeHeld(both, false, false); n != 0 {
		t.Fatalf("the first miss after a gap marked %d", n)
	}
	if rec, _ := g.effectOf(d); !rec.Gone.IsZero() {
		t.Fatalf("a block missed only once in a row is gone: %+v", rec)
	}
}

// A record that changed between the list and the answer is left to what
// changed it: one swept at its expiry, or a victim a pending block claimed.
func TestAdmissionLedgerObserveHeldSkipsChangedRecords(t *testing.T) {
	f := liveLedgerFixture(t)
	short := f.verifiedWith("192.0.2.10", admission.SeverityWarning, 90*time.Second)
	asked, _ := f.l.HeldEffects(10)
	f.observeHeld(asked, false)
	if n := f.observeHeld(asked, false); n != 0 {
		t.Fatalf("a swept record was marked: %d", n)
	}
	if _, found := f.effectOf(short); found {
		t.Fatal("the short block outlived its expiry")
	}
	g := liveLedgerFixture(t)
	g.l.SetOccupants(&fullGeneral)
	claimed := g.verifiedWith("192.0.2.11", admission.SeverityWarning, time.Hour)
	asked, _ = g.l.HeldEffects(10)
	g.observeHeld(asked, false)
	g.evicting("192.0.2.12", claimed)
	if n := g.observeHeld(asked, false); n != 0 {
		t.Fatalf("a claimed victim was marked: %d", n)
	}
	if rec, _ := g.effectOf(claimed); !rec.Gone.IsZero() || rec.EvictedBy == "" {
		t.Fatalf("the claimed victim changed: %+v", rec)
	}
	if _, _, schema := g.effectRecords(); schema >= admissionSchemaEffectGone {
		t.Fatalf("schema %d with no gone record", schema)
	}
}

// Answers that do not match the list change nothing: they neither count
// as a miss nor reset one.
func TestAdmissionLedgerObserveHeldRefusesMismatchedAnswers(t *testing.T) {
	f := liveLedgerFixture(t)
	f.verifiedWith("192.0.2.10", admission.SeverityWarning, time.Hour)
	asked, _ := f.l.HeldEffects(10)
	refuse := func() {
		t.Helper()
		before := f.snapshot()
		_, err := markedCount(f.l.ObserveHeld(asked, []bool{false, false}))
		wantLedgerReason(t, "mismatched answers", err, admission.ReasonInvalid)
		if !reflect.DeepEqual(before, f.snapshot()) {
			t.Fatal("a refused answer changed the ledger")
		}
	}
	refuse()
	if n := f.observeHeld(asked, false); n != 0 {
		t.Fatalf("a refused answer counted as a miss: %d", n)
	}
	refuse()
	if n := f.observeHeld(asked, false); n != 1 {
		t.Fatalf("a refused answer reset the misses: %d marked", n)
	}
}

// A gone record frees its slot for waiting work and stays, holding
// nothing, until its own expiry sweep.
func TestAdmissionLedgerGoneRecordFreesItsSlot(t *testing.T) {
	f := liveLedgerFixture(t)
	f.l.SetOccupants(&fullGeneral)
	a := f.verifiedWith("192.0.2.10", admission.SeverityWarning, time.Hour)
	waiting := f.queuedWith("192.0.2.11", admission.SeverityWarning)
	if picks, err := f.l.Schedule(allSlots, nil); err != nil || len(picks) != 0 {
		t.Fatalf("a full partition scheduled %+v %v", picks, err)
	}
	asked, _ := f.l.HeldEffects(10)
	f.observeHeld(asked, false)
	f.observeHeld(asked, false)
	picks, err := f.l.Schedule(allSlots, nil)
	if err != nil || len(picks) != 1 || picks[0].ID != waiting {
		t.Fatalf("after the gone mark: %+v %v", picks, err)
	}
	f.tickAt(a.ExpiresAt)
	if _, found := f.effectOf(a); found {
		t.Fatal("the gone record outlived its expiry")
	}
	if _, tally, _ := f.effectRecords(); tally != (admission.EffectTally{}) {
		t.Fatalf("tally %+v after the gone record's sweep, want it unchanged", tally)
	}
}

// A verified eviction is how the ledger learns its victim left: the
// victim's record is gone at the block's verified outcome, with the
// schema that names it.
func TestAdmissionLedgerVerifiedEvictionMarksTheVictimGone(t *testing.T) {
	f := liveLedgerFixture(t)
	f.l.SetOccupants(&fullGeneral)
	low := f.verifiedWith("192.0.2.10", admission.SeverityWarning, time.Hour)
	a := f.evicting("192.0.2.11", low)
	if _, _, _, err := f.l.Execute(a.Attempt.ID); err != nil {
		t.Fatal(err)
	}
	f.tickAt(f.wall.Add(time.Minute))
	if _, _, err := f.l.Finish(a.Attempt.ID, admission.DispositionApplied); err != nil {
		t.Fatal(err)
	}
	victim, _ := f.effectOf(low)
	if !victim.Evicted || !victim.Gone.Equal(f.wall) || victim.Holds() {
		t.Fatalf("evicted victim %+v, want gone at %v", victim, f.wall)
	}
	if _, _, schema := f.effectRecords(); schema != admissionSchemaEffectGone {
		t.Fatalf("schema %d after an eviction", schema)
	}
	if _, err := OpenAdmissionLedger(f.db, f.reg); err != nil {
		t.Fatalf("reopening with an evicted record: %v", err)
	}
}

// Opening proves gone records against the tally and the schema: a gone
// record that still counts or predates schema 14 is damage.
func TestAdmissionLedgerOpenProvesGoneRecords(t *testing.T) {
	for name, damage := range map[string]func(t *testing.T, f *ledgerFixture, rec admission.EffectRecord, tx *bolt.Tx){
		"counted gone record": func(t *testing.T, _ *ledgerFixture, rec admission.EffectRecord, tx *bolt.Tx) {
			if err := addEffectTally(tx, rec.Partition, 1); err != nil {
				t.Fatal(err)
			}
		},
		"gone record below its schema": func(t *testing.T, _ *ledgerFixture, _ admission.EffectRecord, tx *bolt.Tx) {
			if err := tx.Bucket([]byte(admissionMetaBucket)).Put(admissionSchemaKey, []byte{admissionSchemaEpisodeElapsed}); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := liveLedgerFixture(t)
			a := f.verifiedWith("192.0.2.10", admission.SeverityWarning, time.Hour)
			asked, _ := f.l.HeldEffects(10)
			f.observeHeld(asked, false)
			f.observeHeld(asked, false)
			rec, _ := f.effectOf(a)
			if err := f.db.bolt.Update(func(tx *bolt.Tx) error {
				damage(t, f, rec, tx)
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			if _, err := OpenAdmissionLedger(f.db, f.reg); !isCorrupt(err) {
				t.Fatalf("opened: %v", err)
			}
			if name == "gone record below its schema" {
				if _, err := ReadSettledBlockActions(f.db, []string{string(a.Attempt.ID)}); !isCorrupt(err) {
					t.Fatalf("startup accepted a gone record below schema 14: %v", err)
				}
			}
		})
	}
}

// A failed write marks nothing and keeps the misses, so the next miss
// marks the block from its first one.
func TestAdmissionLedgerFailedGoneWriteKeepsTheMisses(t *testing.T) {
	f := liveLedgerFixture(t)
	a := f.verifiedWith("192.0.2.10", admission.SeverityWarning, time.Hour)
	asked, _ := f.l.HeldEffects(10)
	f.observeHeld(asked, false)
	firstMiss := f.wall
	f.tickAt(f.wall.Add(time.Minute))
	before := f.snapshot()
	f.failNext("gone")
	if n, err := markedCount(f.l.ObserveHeld(asked, []bool{false})); err == nil || n != 0 {
		t.Fatalf("a failed write: %d, %v", n, err)
	}
	if !reflect.DeepEqual(before, f.snapshot()) {
		t.Fatal("a failed write changed the ledger")
	}
	if n := f.observeHeld(asked, false); n != 1 {
		t.Fatalf("the miss after a failed write marked %d", n)
	}
	if rec, _ := f.effectOf(a); !rec.Gone.Equal(firstMiss) {
		t.Fatalf("gone at %v, want the first miss %v", rec.Gone, firstMiss)
	}
}

// A mismatched address is not an answered miss and cannot discard an
// earlier valid miss. Refuse the whole answer before changing any state.
func TestAdmissionLedgerObserveHeldNeedsTheRecordsTarget(t *testing.T) {
	f := liveLedgerFixture(t)
	a := f.verifiedWith("192.0.2.10", admission.SeverityWarning, time.Hour)
	asked, _ := f.l.HeldEffects(10)
	f.observeHeld(asked, false)
	first := f.wall
	wrong := append([]HeldEffect(nil), asked...)
	wrong[0].Target = f.target("192.0.2.99")
	before := f.snapshot()
	if n, err := markedCount(f.l.ObserveHeld(wrong, []bool{false})); n != 0 {
		t.Fatalf("mismatched target marked %d", n)
	} else {
		wantLedgerReason(t, "mismatched target", err, admission.ReasonInvalid)
	}
	if !reflect.DeepEqual(before, f.snapshot()) {
		t.Fatal("mismatched target changed the ledger")
	}
	if n := f.observeHeld(asked, false); n != 1 {
		t.Fatalf("valid miss after mismatch marked %d", n)
	}
	if rec, _ := f.effectOf(a); !rec.Gone.Equal(first) {
		t.Fatalf("mismatched target lost the first miss: %+v", rec)
	}
}

// A failed multi-record transaction accepts none of the answer: it
// neither resets an old miss nor starts a new one for another block.
func TestAdmissionLedgerGoneWriteFailureRejectsWholeAnswer(t *testing.T) {
	f := liveLedgerFixture(t)
	a := f.verifiedWith("192.0.2.10", admission.SeverityWarning, time.Hour)
	b := f.verifiedWith("192.0.2.11", admission.SeverityWarning, time.Hour)
	c := f.verifiedWith("192.0.2.12", admission.SeverityWarning, time.Hour)
	asked := []HeldEffect{f.heldOf(a, "192.0.2.10"), f.heldOf(b, "192.0.2.11"), f.heldOf(c, "192.0.2.12")}
	f.observeHeld(asked, false, false, true)
	first := f.wall
	f.tickAt(f.wall.Add(time.Minute))
	before := f.snapshot()
	f.failNext("gone")
	if n, err := markedCount(f.l.ObserveHeld(asked, []bool{false, true, false})); err == nil || n != 0 {
		t.Fatalf("failed answer: %d %v", n, err)
	}
	if !reflect.DeepEqual(before, f.snapshot()) {
		t.Fatal("failed answer committed part of the transaction")
	}
	if n := f.observeHeld(asked, false, false, false); n != 2 {
		t.Fatalf("failed answer changed the misses: marked %d, want 2", n)
	}
	for _, attempt := range []admission.AttemptRecord{a, b} {
		if rec, _ := f.effectOf(attempt); !rec.Gone.Equal(first) {
			t.Fatalf("failed answer lost an earlier miss: %+v", rec)
		}
	}
	if rec, _ := f.effectOf(c); !rec.Gone.IsZero() {
		t.Fatalf("failed answer counted a first miss: %+v", rec)
	}
}

// A claimed victim contributes no first miss. Releasing a failed claim
// makes it eligible again, but two new answered misses are required.
func TestAdmissionLedgerGoneMissStartsOnlyForEligibleRecords(t *testing.T) {
	f := liveLedgerFixture(t)
	f.l.SetOccupants(&fullGeneral)
	low := f.verifiedWith("192.0.2.10", admission.SeverityWarning, time.Hour)
	asked, _ := f.l.HeldEffects(10)
	a := f.evicting("192.0.2.11", low)
	if n := f.observeHeld(asked, false); n != 0 {
		t.Fatalf("claimed first miss marked %d", n)
	}
	if _, _, _, err := f.l.Execute(a.Attempt.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.l.Finish(a.Attempt.ID, admission.DispositionFailed); err != nil {
		t.Fatal(err)
	}
	if n := f.observeHeld(asked, false); n != 0 {
		t.Fatalf("a miss while claimed counted: %d", n)
	}
	first := f.wall
	if n := f.observeHeld(asked, false); n != 1 {
		t.Fatalf("two eligible misses marked %d", n)
	}
	if rec, _ := f.effectOf(low); !rec.Gone.Equal(first) {
		t.Fatalf("gone time includes the claimed interval: %+v", rec)
	}
}

// A gone record never returns to the tally or the victim pool. New
// reservations, verification, failure, duplicate outcomes and expiry
// each change only the slots they own.
func TestAdmissionLedgerGoneTallyStaysExact(t *testing.T) {
	f := liveLedgerFixture(t)
	f.l.SetOccupants(&fullGeneral)
	a := f.verifiedWith("192.0.2.10", admission.SeverityWarning, time.Hour)
	asked, _ := f.l.HeldEffects(10)
	f.observeHeld(asked, false)
	f.observeHeld(asked, false)
	gone, _ := f.effectOf(a)
	other, err := admission.NewAttempt(a.Attempt.Candidate, a.Attempt.Seq+1)
	if err != nil {
		t.Fatal(err)
	}
	before := f.snapshot()
	err = f.db.bolt.Update(func(tx *bolt.Tx) error {
		q := queueTx{tx: tx, now: f.wall}
		return q.claimVictim(admission.EffectRef{Action: a.Attempt.ID, ExpiresAt: a.ExpiresAt}, other.ID)
	})
	if !isCorrupt(err) || !reflect.DeepEqual(before, f.snapshot()) {
		t.Fatalf("a gone victim was claimed: %v", err)
	}
	_, b, _, err := f.l.Reserve(f.queuedWith("192.0.2.11", admission.SeverityCritical), admission.LaneGeneral, f.wall.Add(2*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if rec, _ := f.effectOf(b); rec.Victim != (admission.EffectRef{}) {
		t.Fatalf("reservation reused a gone victim: %+v", rec)
	}
	if _, _, _, err = f.l.Execute(b.Attempt.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err = f.l.Finish(b.Attempt.ID, admission.DispositionFailed); err != nil {
		t.Fatal(err)
	}
	c := f.verifiedWith("192.0.2.12", admission.SeverityWarning, 2*time.Hour)
	if _, _, err = f.l.Finish(c.Attempt.ID, admission.DispositionApplied); err != nil {
		t.Fatal(err)
	}
	for _, answer := range []bool{true, false, false} {
		if n := f.observeHeld(asked, answer); n != 0 {
			t.Fatalf("a final gone mark changed: %d", n)
		}
	}
	if rec, _ := f.effectOf(a); rec != gone {
		t.Fatalf("gone record changed: %+v, want %+v", rec, gone)
	}
	f.tickAt(a.ExpiresAt)
	if _, found := f.effectOf(a); found {
		t.Fatal("gone record survived its expiry")
	}
	if _, tally, schema := f.effectRecords(); tally != (admission.EffectTally{General: 1}) || schema != admissionSchemaEffectGone {
		t.Fatalf("gone sweep changed another slot: %+v schema %d", tally, schema)
	}
	if got, err := f.l.HeldEffects(10); err != nil || !reflect.DeepEqual(got, []HeldEffect{f.heldOf(c, "192.0.2.12")}) {
		t.Fatalf("held after gone sweep: %+v %v", got, err)
	}
	if _, err := OpenAdmissionLedger(f.db, f.reg); err != nil {
		t.Fatalf("reopen after gone sweep: %v", err)
	}
}

// Absence needs no trusted wall clock; a process restart discards only
// the unfinished miss and never changes a committed gone mark.
func TestAdmissionLedgerGoneMissesSurviveClockButNotRestart(t *testing.T) {
	f := liveLedgerFixture(t)
	a := f.verifiedWith("192.0.2.10", admission.SeverityWarning, time.Hour)
	asked, _ := f.l.HeldEffects(10)
	f.observeHeld(asked, false)
	var err error
	f.l, err = OpenAdmissionLedger(f.db, f.reg)
	if err != nil {
		t.Fatal(err)
	}
	f.tickAt(f.wall)
	if tick, err := f.l.Tick(admission.ClockReading{Wall: f.wall.Add(2 * time.Hour), BootID: ledgerBoot, SinceBoot: f.since + time.Minute}); err != nil || !tick.Degraded {
		t.Fatalf("forward step: %+v %v", tick, err)
	}
	if n, err := markedCount(f.l.ObserveHeld(asked, []bool{false})); err != nil || n != 0 {
		t.Fatalf("restart kept a first miss: %d %v", n, err)
	}
	first := f.l.now
	if n, err := markedCount(f.l.ObserveHeld(asked, []bool{false})); err != nil || n != 1 {
		t.Fatalf("degraded clock prevented absence proof: %d %v", n, err)
	}
	if rec, _ := f.effectOf(a); !rec.Gone.Equal(first) {
		t.Fatalf("gone time: %+v, want %v", rec, first)
	}
	if _, err := OpenAdmissionLedger(f.db, f.reg); err != nil {
		t.Fatal(err)
	}
}

// The configured capacity may exceed one engine call. Two answered
// checks per batch give every retained block consecutive observations
// without letting a held prefix starve later records.
func TestAdmissionLedgerGoneChecksReachEveryBatch(t *testing.T) {
	f := liveLedgerFixture(t)
	a := f.verifiedWith("192.0.2.10", admission.SeverityWarning, time.Hour)
	b := f.verifiedWith("192.0.2.11", admission.SeverityWarning, 2*time.Hour)
	c := f.verifiedWith("192.0.2.12", admission.SeverityWarning, 3*time.Hour)
	for i, want := range []HeldEffect{
		f.heldOf(a, "192.0.2.10"), f.heldOf(a, "192.0.2.10"),
		f.heldOf(b, "192.0.2.11"), f.heldOf(b, "192.0.2.11"),
		f.heldOf(c, "192.0.2.12"), f.heldOf(c, "192.0.2.12"),
		f.heldOf(a, "192.0.2.10"),
	} {
		asked, err := f.l.HeldEffects(1)
		if err != nil || !reflect.DeepEqual(asked, []HeldEffect{want}) {
			t.Fatalf("batch %d: %+v %v, want %+v", i, asked, err, want)
		}
		before := f.snapshot()
		if _, err := markedCount(f.l.ObserveHeld(asked, nil)); err == nil || !reflect.DeepEqual(before, f.snapshot()) {
			t.Fatalf("refused answer changed batch %d: %v", i, err)
		}
		if again, err := f.l.HeldEffects(1); err != nil || !reflect.DeepEqual(again, asked) {
			t.Fatalf("refused answer advanced the batch: %+v %v", again, err)
		}
		n := f.observeHeld(asked, i != 4 && i != 5)
		wantGone := 0
		if i == 5 {
			wantGone = 1
		}
		if n != wantGone {
			t.Fatalf("batch %d marked %d, want %d", i, n, wantGone)
		}
	}
}

// markedCount is how many blocks an answer marked gone.
func markedCount(gone []HeldEffect, err error) (int, error) { return len(gone), err }

// An answer reports the blocks it marked gone, so the owner can retire
// any row their elements left behind.
func TestAdmissionLedgerObserveHeldReturnsTheMarkedBlocks(t *testing.T) {
	f := liveLedgerFixture(t)
	a := f.verifiedWith("192.0.2.10", admission.SeverityWarning, time.Hour)
	b := f.verifiedWith("192.0.2.11", admission.SeverityWarning, 2*time.Hour)
	asked, _ := f.l.HeldEffects(10)
	f.observeHeld(asked, false, true)
	f.tickAt(f.wall.Add(time.Minute))
	gone, err := f.l.ObserveHeld(asked, []bool{false, true})
	if want := []HeldEffect{f.heldOf(a, "192.0.2.10")}; err != nil || !reflect.DeepEqual(gone, want) {
		t.Fatalf("marked %+v %v, want %+v", gone, err, want)
	}
	if rec, _ := f.effectOf(b); !rec.Gone.IsZero() {
		t.Fatalf("a held block was marked: %+v", rec)
	}
}
