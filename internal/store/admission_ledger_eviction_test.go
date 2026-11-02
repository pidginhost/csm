package store

import (
	"reflect"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	bolt "go.etcd.io/bbolt"
)

// queuedWith enqueues a block of target from a local root of severity.
func (f *ledgerFixture) queuedWith(target string, severity admission.Severity) admission.CandidateID {
	f.t.Helper()
	root := f.published(evidenceSpec{target: target, cursor: "evict-" + target, severity: severity})
	_, id := f.enqueue(f.request(target, root))
	return id
}

// verifiedWith is a verified general block of target and severity that
// expires after ttl: a record that strictly higher work may evict.
func (f *ledgerFixture) verifiedWith(target string, severity admission.Severity, ttl time.Duration) admission.AttemptRecord {
	f.t.Helper()
	_, a, _, err := f.l.Reserve(f.queuedWith(target, severity), admission.LaneGeneral, f.wall.Add(ttl))
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

// effectOf is the stored record of attempt a.
func (f *ledgerFixture) effectOf(a admission.AttemptRecord) (admission.EffectRecord, bool) {
	f.t.Helper()
	records, _, _ := f.effectRecords()
	for _, r := range records {
		if r.Action == a.Attempt.ID {
			return r, true
		}
	}
	return admission.EffectRecord{}, false
}

// fullGeneral leaves one general and one reserved slot of the set, so a
// single general record fills the general partition.
var fullGeneral = admission.SetOccupancy{Limit: 5, Unclaimed: 3}

// A full general partition yields to strictly higher work: the
// reservation claims the victim under the lock, before any charge, and
// the block's record takes the victim's partition and names it. Pending
// and live reservations count together until the outcome.
func TestAdmissionLedgerReserveClaimsALowerVictim(t *testing.T) {
	f := liveLedgerFixture(t)
	f.l.SetOccupants(&fullGeneral)
	low := f.verifiedWith("192.0.2.10", admission.SeverityWarning, time.Hour)
	high := f.queuedWith("192.0.2.11", admission.SeverityCritical)
	_, a, _, err := f.l.Reserve(high, admission.LaneGeneral, f.wall.Add(2*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	member, _ := f.effectOf(a)
	victim, _ := f.effectOf(low)
	if member.Victim != (admission.EffectRef{Action: low.Attempt.ID, ExpiresAt: low.ExpiresAt}) || member.Partition != admission.PartitionGeneral {
		t.Fatalf("member record %+v", member)
	}
	if victim.EvictedBy != a.Attempt.ID || victim.Evicted || !victim.Holds() {
		t.Fatalf("victim record %+v", victim)
	}
	if _, tally, _ := f.effectRecords(); tally != (admission.EffectTally{General: 2}) {
		t.Fatalf("tally %+v, want both counted until the outcome", tally)
	}
	if err = f.db.bolt.View(func(tx *bolt.Tx) error {
		pool, poolErr := victimPool(tx, f.wall, nil)
		if poolErr == nil && len(pool) != 0 {
			t.Fatalf("claimed records remained in the pool: %+v", pool)
		}
		return poolErr
	}); err != nil {
		t.Fatal(err)
	}
	for name, sev := range map[string]admission.Severity{"another critical block": admission.SeverityCritical, "equal tier": admission.SeverityWarning} {
		id := f.queuedWith("192.0.2."+map[string]string{"another critical block": "12", "equal tier": "13"}[name], sev)
		before := f.snapshot()
		_, _, _, err = f.l.Reserve(id, admission.LaneGeneral, f.wall.Add(time.Hour))
		wantLedgerReason(t, name, err, admission.ReasonSetFull)
		if !reflect.DeepEqual(before, f.snapshot()) {
			t.Fatalf("%s: a refused reservation changed the ledger", name)
		}
	}
}

// A free slot is taken before anyone is evicted.
func TestAdmissionLedgerReserveTakesAFreeSlotFirst(t *testing.T) {
	f := liveLedgerFixture(t)
	f.l.SetOccupants(&admission.SetOccupancy{Limit: 5, Unclaimed: 2})
	low := f.verifiedWith("192.0.2.10", admission.SeverityWarning, time.Hour)
	_, a, _, err := f.l.Reserve(f.queuedWith("192.0.2.11", admission.SeverityCritical), admission.LaneGeneral, f.wall.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if member, _ := f.effectOf(a); member.Victim != (admission.EffectRef{}) {
		t.Fatalf("evicted with a free slot: %+v", member)
	}
	if victim, _ := f.effectOf(low); victim.EvictedBy != "" {
		t.Fatalf("victim claimed with a free slot: %+v", victim)
	}
}

// Reserved work evicts a lower general entry across partitions and keeps
// that slot general, its lane charge reserved.
func TestAdmissionLedgerReservedWorkReplacesAGeneralEntry(t *testing.T) {
	f := liveLedgerFixture(t)
	// Two slots: the reserved one taken by an unclaimed entry, the
	// general one by a lower record.
	f.l.SetOccupants(&admission.SetOccupancy{Limit: 5, Unclaimed: 3})
	low := f.verifiedWith("192.0.2.10", admission.SeverityHigh, time.Hour)
	if _, _, _, err := f.l.Reserve(f.directAt("192.0.2.20"), admission.LaneDirect, f.wall.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	_, a, _, err := f.l.Reserve(f.directAt("192.0.2.21"), admission.LaneDirect, f.wall.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	member, _ := f.effectOf(a)
	if member.Partition != admission.PartitionGeneral || member.Lane != admission.LaneDirect || member.Victim.Action != low.Attempt.ID {
		t.Fatalf("member record %+v", member)
	}
}

// A schedule serves only work a free slot or a victim it outranks can
// take; the rest waits as set_full, and one victim funds one pick.
func TestAdmissionLedgerScheduleFundsWorkWithVictims(t *testing.T) {
	f := liveLedgerFixture(t)
	f.l.SetOccupants(&fullGeneral)
	low := f.verifiedWith("192.0.2.10", admission.SeverityWarning, time.Hour)
	first, second := f.queuedWith("192.0.2.11", admission.SeverityCritical), f.queuedWith("192.0.2.12", admission.SeverityCritical)
	equal := f.queuedWith("192.0.2.13", admission.SeverityWarning)
	picks, err := f.l.Schedule(allSlots, nil)
	if err != nil || len(picks) != 1 || (picks[0].ID != first && picks[0].ID != second) || picks[0].Lane != admission.LaneGeneral {
		t.Fatalf("picks %+v %v, want one critical block", picks, err)
	}
	waiting := first
	if picks[0].ID == first {
		waiting = second
	}
	for _, id := range []admission.CandidateID{waiting, equal} {
		if c := f.candidateOf(id); c.Reason != admission.ReasonSetFull {
			t.Fatalf("%s waits as %s, want set_full", id, c.Reason)
		}
	}
	if _, _, _, err = f.l.Reserve(picks[0].ID, admission.LaneGeneral, f.wall.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if victim, _ := f.effectOf(low); victim.EvictedBy == "" {
		t.Fatal("the reservation did not claim the victim the schedule counted")
	}
}

// Work no victim can fund never wakes the owner at once: it waits for an
// expiry or the set recheck, as a full set without victims does.
func TestAdmissionLedgerWakeIgnoresVictimsWorkCannotTake(t *testing.T) {
	f := liveLedgerFixture(t)
	f.l.SetOccupants(&fullGeneral)
	f.verifiedWith("192.0.2.10", admission.SeverityHigh, time.Hour)
	f.queuedWith("192.0.2.11", admission.SeverityWarning)
	if picks, err := f.l.Schedule(allSlots, nil); err != nil || len(picks) != 0 {
		t.Fatalf("picks %+v %v", picks, err)
	}
	if wake, ok, err := f.l.NextWake(nil); err != nil || !ok || !wake.Equal(f.wall.Add(setRecheck)) {
		t.Fatalf("wake %v %v %v, want the set recheck", wake, ok, err)
	}
	f.queuedWith("192.0.2.12", admission.SeverityCritical)
	if wake, ok, err := f.l.NextWake(nil); err != nil || !ok || !wake.Equal(f.wall) {
		t.Fatalf("wake %v %v %v, want now for work a victim funds", wake, ok, err)
	}
}

// A preview models the eviction without claiming anything.
func TestAdmissionLedgerObserveModelsEvictionWithoutAClaim(t *testing.T) {
	f := liveLedgerFixture(t)
	f.l.SetOccupants(&fullGeneral)
	low := f.verifiedWith("192.0.2.10", admission.SeverityWarning, time.Hour)
	id := f.queuedWith("192.0.2.11", admission.SeverityCritical)
	before, beforeTally, _ := f.effectRecords()
	if _, _, _, err := f.l.Observe(id, admission.LaneGeneral, f.wall.Add(time.Hour)); err != nil {
		t.Fatalf("preview of funded work: %v", err)
	}
	if victim, _ := f.effectOf(low); victim.EvictedBy != "" {
		t.Fatalf("a preview claimed its victim: %+v", victim)
	}
	if _, _, _, err := f.l.Observe(f.queuedWith("192.0.2.12", admission.SeverityWarning), admission.LaneGeneral, f.wall.Add(time.Hour)); err == nil {
		t.Fatal("a preview of equal work took the slot")
	}
	if after, tally, _ := f.effectRecords(); tally != beforeTally || !reflect.DeepEqual(before, after) {
		t.Fatalf("preview changed slots: %+v %+v", after, tally)
	}
	if _, err := OpenAdmissionLedger(f.db, f.reg); err != nil {
		t.Fatalf("preview cannot reopen: %v", err)
	}
}

// Opening proves every claim from both ends: a claimed victim and the
// pending block that names it agree, and only held slots are tallied.
func TestAdmissionLedgerOpenProvesEvictionClaims(t *testing.T) {
	for name, damage := range map[string]func(t *testing.T, tx *bolt.Tx, member, victim admission.EffectRecord){
		"victim names another block": func(t *testing.T, tx *bolt.Tx, member, victim admission.EffectRecord) {
			victim.EvictedBy = admission.ActionID("act_00000000000000000000000000000009")
			putEffectForTest(t, tx, victim)
		},
		"claim released on one side": func(t *testing.T, tx *bolt.Tx, member, victim admission.EffectRecord) {
			victim.EvictedBy = ""
			putEffectForTest(t, tx, victim)
		},
		"block forgets its victim": func(t *testing.T, tx *bolt.Tx, member, victim admission.EffectRecord) {
			member.Victim = admission.EffectRef{}
			putEffectForTest(t, tx, member)
		},
		"pending block's victim marked evicted": func(t *testing.T, tx *bolt.Tx, member, victim admission.EffectRecord) {
			victim.Evicted = true
			putEffectForTest(t, tx, victim)
			tally, err := loadEffectTally(tx)
			if err != nil {
				t.Fatal(err)
			}
			if tally, err = tally.Add(admission.PartitionGeneral, -1); err != nil {
				t.Fatal(err)
			}
			if err = putEffectTally(tx, tally); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := liveLedgerFixture(t)
			f.l.SetOccupants(&fullGeneral)
			low := f.verifiedWith("192.0.2.10", admission.SeverityWarning, time.Hour)
			_, a, _, err := f.l.Reserve(f.queuedWith("192.0.2.11", admission.SeverityCritical), admission.LaneGeneral, f.wall.Add(2*time.Hour))
			if err != nil {
				t.Fatal(err)
			}
			if _, err = OpenAdmissionLedger(f.db, f.reg); err != nil {
				t.Fatalf("a ledger with a live claim: %v", err)
			}
			member, _ := f.effectOf(a)
			victim, _ := f.effectOf(low)
			if err = f.db.bolt.Update(func(tx *bolt.Tx) error {
				damage(t, tx, member, victim)
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			if _, err = OpenAdmissionLedger(f.db, f.reg); !isCorrupt(err) {
				t.Fatalf("opened: %v", err)
			}
		})
	}
}

func putEffectForTest(t *testing.T, tx *bolt.Tx, rec admission.EffectRecord) {
	t.Helper()
	key, err := rec.Key()
	if err != nil {
		t.Fatal(err)
	}
	data, err := rec.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if err = tx.Bucket([]byte(admissionEffectsBucket)).Put(key, data); err != nil {
		t.Fatal(err)
	}
}

// A block whose application is unverified may never have been enforced,
// so it is never a victim.
func TestAdmissionLedgerPendingBlocksAreNeverVictims(t *testing.T) {
	f := liveLedgerFixture(t)
	f.l.SetOccupants(&fullGeneral)
	if _, _, _, err := f.l.Reserve(f.queuedWith("192.0.2.10", admission.SeverityWarning), admission.LaneGeneral, f.wall.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	_, _, _, err := f.l.Reserve(f.queuedWith("192.0.2.11", admission.SeverityCritical), admission.LaneGeneral, f.wall.Add(time.Hour))
	wantLedgerReason(t, "a pending block", err, admission.ReasonSetFull)
}

// Picks compete for victims in schedule order: a pick that the earlier
// picks left no victim waits, and the schedule serves the rest.
func TestAdmissionLedgerScheduleRechecksContendedVictims(t *testing.T) {
	f := liveLedgerFixture(t)
	// Three slots: one reserved, two general, both taken below.
	f.l.SetOccupants(&admission.SetOccupancy{Limit: 10, Unclaimed: 7})
	f.verifiedWith("192.0.2.10", admission.SeverityWarning, time.Hour)
	f.verifiedWith("192.0.2.11", admission.SeverityHigh, time.Hour)
	first, second := f.queuedWith("192.0.2.20", admission.SeverityHigh), f.queuedWith("192.0.2.21", admission.SeverityHigh)
	picks, err := f.l.Schedule(allSlots, nil)
	if err != nil || len(picks) != 1 {
		t.Fatalf("picks %+v %v, want one: one victim is below High", picks, err)
	}
	waiting := first
	if picks[0].ID == first {
		waiting = second
	}
	if c := f.candidateOf(waiting); c.Reason != admission.ReasonSetFull {
		t.Fatalf("the contended pick waits as %s, want set_full", c.Reason)
	}
}

// evicting reserves a critical block at target that claims victim.
func (f *ledgerFixture) evicting(target string, victim admission.AttemptRecord) admission.AttemptRecord {
	f.t.Helper()
	_, a, _, err := f.l.Reserve(f.queuedWith(target, admission.SeverityCritical), admission.LaneGeneral, f.wall.Add(2*time.Hour))
	if err != nil {
		f.t.Fatal(err)
	}
	if member, _ := f.effectOf(a); member.Victim.Action != victim.Attempt.ID {
		f.t.Fatalf("the block claimed %+v, want %s", member.Victim, victim.Attempt.ID)
	}
	return a
}

// The intent of an evicting block names its victim, so a restart knows
// which block the batch may have removed.
func TestAdmissionLedgerIntentNamesTheVictim(t *testing.T) {
	f := liveLedgerFixture(t)
	f.l.SetOccupants(&fullGeneral)
	low := f.verifiedWith("192.0.2.10", admission.SeverityWarning, time.Hour)
	a := f.evicting("192.0.2.11", low)
	intents, _, err := f.l.ExecuteBatch([]admission.ActionID{a.Attempt.ID})
	want := admission.Victim{Action: low.Attempt.ID, Target: f.target("192.0.2.10"), ExpiresAt: low.ExpiresAt}
	if err != nil || len(intents) != 1 || intents[0].Victim != want || f.intents()[a.Attempt.ID].Victim != want {
		t.Fatalf("intents %+v %v, want victim %+v", intents, err, want)
	}
}

// A verified eviction ends the victim's hold in the same transaction: the
// victim's record is kept as evicted until its expiry, holds no slot and
// never ends a wait; the block keeps the slot.
func TestAdmissionLedgerVerifiedEvictionEndsTheVictimsHold(t *testing.T) {
	f := liveLedgerFixture(t)
	f.l.SetOccupants(&fullGeneral)
	// The victim ends before the set recheck, so a wake at its expiry
	// would show.
	low := f.verifiedWith("192.0.2.10", admission.SeverityWarning, 30*time.Second)
	a := f.evicting("192.0.2.11", low)
	if _, _, _, err := f.l.Execute(a.Attempt.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.l.Finish(a.Attempt.ID, admission.DispositionApplied); err != nil {
		t.Fatal(err)
	}
	member, _ := f.effectOf(a)
	victim, _ := f.effectOf(low)
	if !member.Verified() || member.Victim != (admission.EffectRef{}) || !victim.Evicted || victim.EvictedBy != a.Attempt.ID || victim.Holds() {
		t.Fatalf("after the verified eviction: member %+v victim %+v", member, victim)
	}
	if _, tally, _ := f.effectRecords(); tally != (admission.EffectTally{General: 1}) {
		t.Fatalf("tally %+v, want the block's slot only", tally)
	}
	if s := f.l.Status().Effects; s.General != 1 || !s.Next.Equal(a.ExpiresAt) || s.Error != "" {
		t.Fatalf("status %+v, want the block's expiry next", s)
	}
	f.queuedWith("192.0.2.12", admission.SeverityCritical)
	if _, err := f.l.Schedule(allSlots, nil); err != nil {
		t.Fatal(err)
	}
	if wake, ok, err := f.l.NextWake(nil); err != nil || !ok || !wake.Equal(f.wall.Add(setRecheck)) {
		t.Fatalf("wake %v %v %v, want the recheck: an evicted record frees nothing at its expiry", wake, ok, err)
	}
	f.tickAt(low.ExpiresAt)
	if _, found := f.effectOf(low); found {
		t.Fatal("the evicted record outlived its expiry")
	}
	if _, tally, _ := f.effectRecords(); tally != (admission.EffectTally{General: 1}) {
		t.Fatalf("tally %+v after the evicted record's sweep, want it unchanged", tally)
	}
}

// A block that fails gives its claim back: the victim returns to the pool
// with its slot, and the block's record leaves.
func TestAdmissionLedgerFailedEvictionReleasesTheClaim(t *testing.T) {
	for _, executed := range []bool{false, true} {
		f := liveLedgerFixture(t)
		f.l.SetOccupants(&fullGeneral)
		low := f.verifiedWith("192.0.2.10", admission.SeverityWarning, time.Hour)
		a := f.evicting("192.0.2.11", low)
		if executed {
			if _, _, _, err := f.l.Execute(a.Attempt.ID); err != nil {
				t.Fatal(err)
			}
		}
		if _, _, err := f.l.Finish(a.Attempt.ID, admission.DispositionFailed); err != nil {
			t.Fatal(err)
		}
		if _, found := f.effectOf(a); found {
			t.Fatal("a failed block kept its record")
		}
		if victim, _ := f.effectOf(low); victim.EvictedBy != "" || victim.Evicted || !victim.Holds() {
			t.Fatalf("executed %v: victim %+v kept the failed claim", executed, victim)
		}
		if _, tally, _ := f.effectRecords(); tally != (admission.EffectTally{General: 1}) {
			t.Fatalf("tally %+v", tally)
		}
		f.evicting("192.0.2.12", low)
	}
}

// An unknown outcome keeps both records as they were: the victim may
// still be enforced, so it keeps its slot, stays claimed and is no one
// else's victim, also once the uncertainty is retired.
func TestAdmissionLedgerUnknownEvictionKeepsBoth(t *testing.T) {
	f := liveLedgerFixture(t)
	f.l.SetOccupants(&fullGeneral)
	low := f.verifiedWith("192.0.2.10", admission.SeverityWarning, 3*time.Hour)
	a := f.evicting("192.0.2.11", low)
	if _, _, _, err := f.l.Execute(a.Attempt.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.l.Finish(a.Attempt.ID, admission.DispositionUnknown); err != nil {
		t.Fatal(err)
	}
	member, _ := f.effectOf(a)
	victim, _ := f.effectOf(low)
	if member.Victim.Action != low.Attempt.ID || victim.EvictedBy != a.Attempt.ID || victim.Evicted {
		t.Fatalf("after an unknown outcome: member %+v victim %+v", member, victim)
	}
	_, _, _, err := f.l.Reserve(f.queuedWith("192.0.2.12", admission.SeverityCritical), admission.LaneGeneral, f.wall.Add(time.Hour))
	wantLedgerReason(t, "a claimed victim", err, admission.ReasonSetFull)
	f.tickAt(a.ExpiresAt)
	if victim, _ = f.effectOf(low); victim.EvictedBy != a.Attempt.ID {
		t.Fatalf("the claim ended with the block's own record: %+v", victim)
	}
	if _, err := OpenAdmissionLedger(f.db, f.reg); err != nil {
		t.Fatalf("a claim whose block was swept: %v", err)
	}
}

// A victim can reach its own expiry before the block that claimed it runs:
// the sweep frees its slot, the intent then names no victim and the
// verified outcome has nothing left to evict.
func TestAdmissionLedgerVictimExpiresBeforeTheOutcome(t *testing.T) {
	f := liveLedgerFixture(t)
	f.l.SetOccupants(&fullGeneral)
	low := f.verifiedWith("192.0.2.10", admission.SeverityWarning, time.Minute)
	a := f.evicting("192.0.2.11", low)
	f.tickAt(low.ExpiresAt)
	if _, found := f.effectOf(low); found {
		t.Fatal("the claimed victim outlived its expiry")
	}
	if _, tally, _ := f.effectRecords(); tally != (admission.EffectTally{General: 1}) {
		t.Fatalf("tally %+v after the victim's sweep", tally)
	}
	intents, _, err := f.l.ExecuteBatch([]admission.ActionID{a.Attempt.ID})
	if err != nil || len(intents) != 1 || intents[0].Victim != (admission.Victim{}) {
		t.Fatalf("intents %+v %v, want no victim", intents, err)
	}
	if _, _, err = f.l.Finish(a.Attempt.ID, admission.DispositionApplied); err != nil {
		t.Fatal(err)
	}
	if member, _ := f.effectOf(a); !member.Verified() || member.Victim != (admission.EffectRef{}) {
		t.Fatalf("member %+v", member)
	}
	if _, tally, _ := f.effectRecords(); tally != (admission.EffectTally{General: 1}) {
		t.Fatalf("tally %+v", tally)
	}
	if _, err = OpenAdmissionLedger(f.db, f.reg); err != nil {
		t.Fatal(err)
	}
}

// Opening proves an evicting intent against its block's claim.
func TestAdmissionLedgerOpenProvesTheIntentVictim(t *testing.T) {
	f := liveLedgerFixture(t)
	f.l.SetOccupants(&fullGeneral)
	low := f.verifiedWith("192.0.2.10", admission.SeverityWarning, time.Hour)
	a := f.evicting("192.0.2.11", low)
	intents, _, err := f.l.ExecuteBatch([]admission.ActionID{a.Attempt.ID})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = OpenAdmissionLedger(f.db, f.reg); err != nil {
		t.Fatalf("an intact evicting intent: %v", err)
	}
	in := intents[0]
	in.Victim.Action = admission.ActionID("act_00000000000000000000000000000009")
	data, err := in.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if err = f.db.bolt.Update(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte(admissionIntentsBucket)).Put([]byte(a.Attempt.ID), data)
	}); err != nil {
		t.Fatal(err)
	}
	if _, err = OpenAdmissionLedger(f.db, f.reg); !isCorrupt(err) {
		t.Fatalf("opened with an intent naming another victim: %v", err)
	}
}

// A free reserved slot prevents eviction on a general turn even when
// only the general lane has credit. Every wake probe must respect that.
func TestAdmissionLedgerEvictionWakeUsesTheFundableLane(t *testing.T) {
	for _, short := range []string{"ceiling", "history"} {
		t.Run(short, func(t *testing.T) {
			f := liveLedgerFixture(t)
			f.l.SetOccupants(&fullGeneral)
			f.verifiedWith("192.0.2.10", admission.SeverityWarning, time.Hour)
			f.directAt("192.0.2.11")
			if short == "ceiling" {
				f.leaveCeilingCredit(1, 0)
			} else {
				f.adjustStorage(func(s *admission.StorageState) { s.Reserved.Credit = 0 })
			}
			if picks, err := f.l.Schedule(allSlots, nil); err != nil || len(picks) != 0 {
				t.Fatalf("unfunded lane picked: %+v %v", picks, err)
			}
			before := f.snapshot()
			for range 3 {
				wake, ok, err := f.l.NextWake(nil)
				if err != nil || !ok || !wake.After(f.wall) {
					t.Fatalf("unfunded lane wakes now: %v %v %v", wake, ok, err)
				}
			}
			if !reflect.DeepEqual(before, f.snapshot()) {
				t.Fatal("wake mutated the ledger")
			}
		})
	}
}

// Replacement preserves occupancy; it cannot fix an overfull partition
// or fund work from a retained record whose own expiry already passed.
func TestAdmissionLedgerEvictionNeedsLiveFittingVictims(t *testing.T) {
	for _, pressure := range []string{"overfull", "expired"} {
		t.Run(pressure, func(t *testing.T) {
			f := liveLedgerFixture(t)
			f.l.SetOccupants(&fullGeneral)
			f.verifiedWith("192.0.2.10", admission.SeverityWarning, time.Minute)
			if pressure == "overfull" {
				f.l.SetOccupants(&admission.SetOccupancy{Limit: 1})
			} else {
				tick, err := f.l.Tick(admission.ClockReading{Wall: f.wall.Add(2 * time.Minute), BootID: ledgerBoot, SinceBoot: f.since})
				if err != nil || !tick.Degraded {
					t.Fatalf("degraded tick %+v %v", tick, err)
				}
			}
			id := f.queuedWith("192.0.2.11", admission.SeverityCritical)
			if picks, err := f.l.Schedule(allSlots, nil); err != nil || len(picks) != 0 {
				t.Fatalf("unusable victim funded picks: %+v %v", picks, err)
			}
			before := f.snapshot()
			_, _, _, err := f.l.Reserve(id, admission.LaneGeneral, f.wall.Add(time.Hour))
			wantLedgerReason(t, "unusable victim", err, admission.ReasonSetFull)
			if !reflect.DeepEqual(before, f.snapshot()) {
				t.Fatal("refused reservation changed the ledger")
			}
		})
	}
}

// Refusing an earlier pick restores room to a contended candidate in the
// same call; a temporary lane exclusion cannot survive that replan.
func TestAdmissionLedgerEvictionReplansAfterRefusal(t *testing.T) {
	f, raise := newFloorLedger(t)
	raise(admission.SeverityWarning)
	if err := f.l.StartLive(admission.LegacyHandover{}); err != nil {
		t.Fatal(err)
	}
	f.l.SetOccupants(&admission.SetOccupancy{Limit: 10, Unclaimed: 7})
	f.verifiedWith("192.0.2.10", admission.SeverityWarning, time.Hour)
	f.verifiedWith("192.0.2.11", admission.SeverityCritical, time.Hour)
	r := f.published(evidenceSpec{owner: f.owner("alice"), target: "192.0.2.20", cursor: "refused", severity: admission.SeverityHigh})
	_, refused := f.enqueue(f.request("192.0.2.20", r))
	r = f.published(evidenceSpec{owner: f.owner("bob"), target: "192.0.2.21", cursor: "kept", severity: admission.SeverityCritical})
	_, kept := f.enqueue(f.request("192.0.2.21", r))
	f.schedule(admission.ScheduleLimits{Members: 1})
	raise(admission.SeverityCritical)
	picks := f.schedule(allSlots)
	if len(picks) != 1 || picks[0].ID != kept || picks[0].Lane != admission.LaneGeneral {
		t.Fatalf("refused pick hid the funded candidate: %+v", picks)
	}
	if c := f.candidateOf(refused); c.State != admission.StateRefused || c.Reason != admission.ReasonPolicy {
		t.Fatalf("invalid pick survived: %+v", c)
	}
}

// Slot pressure pauses a saved ceiling turn without spending or forgetting
// its earned credits. Uncharged work can run, and the saved turn resumes
// before new work when its lane has room again.
func TestAdmissionLedgerSlotPressureKeepsCeilingTurns(t *testing.T) {
	for _, lane := range []admission.Lane{admission.LaneGeneral, admission.LaneDirect, admission.LaneCorroborated} {
		t.Run(lane.String(), func(t *testing.T) {
			paid := admission.ScheduleItem{ID: "paid", Scope: "held", Tier: admission.Tier{Class: admission.ClassC2, Severity: admission.SeverityHigh}, Cost: 1, CeilingCost: 1, Bytes: 10000, Ready: true}
			if lane != admission.LaneGeneral {
				paid.Tier.Class = admission.ClassC3
				paid.Direct, paid.Corroborated = lane == admission.LaneDirect, lane == admission.LaneCorroborated
			}
			free := paid
			free.ID, free.Scope, free.CeilingCost, free.Bytes = "free", "other", 0, 1
			lim := admission.ScheduleLimits{Members: 1, GeneralBytes: 1000, ReservedBytes: 1000}
			earning := lim
			if lane == admission.LaneGeneral {
				earning.General = 1
			} else {
				earning.Reserved = 1
			}
			picks, st, err := admission.Schedule([]admission.ScheduleItem{paid}, admission.ScheduleState{}, earning)
			if err != nil || len(picks) != 0 {
				t.Fatalf("history shortage did not save credits: %+v %v", picks, err)
			}
			picks, st, err = admission.Schedule([]admission.ScheduleItem{paid, free}, st, lim)
			hold := func(s admission.ScheduleState) *admission.CeilingHold {
				if lane == admission.LaneGeneral {
					return s.GeneralHold
				}
				return s.ReservedHold
			}
			if err != nil || len(picks) != 1 || picks[0].ID != free.ID || hold(st) == nil || hold(st).ID != paid.ID {
				t.Fatalf("ceiling turn was not parked: %+v %+v %v", picks, st, err)
			}
			want := *hold(st)
			if want.Turn.Deficit == 0 || want.Turn.Bytes < paid.Bytes {
				t.Fatalf("saved turn has no earned credits: %+v", want)
			}
			byID := map[admission.CandidateID]liveCandidate{
				paid.ID: {c: admission.Candidate{Key: admission.CandidateKey{Kind: admission.KindBlockIP}}},
				free.ID: {c: admission.Candidate{Key: admission.CandidateKey{Kind: admission.KindChallenge}}},
			}
			for range 3 {
				items := slotReady([]admission.ScheduleItem{paid, free}, byID, admission.NewSlotLimits(0, 0, nil))
				picks, st, err = admission.Schedule(items, st, lim)
				if err != nil || len(picks) != 1 || picks[0].ID != free.ID || hold(st) == nil || *hold(st) != want {
					t.Fatalf("slot pressure lost the ceiling turn: %+v %+v %v", picks, st, err)
				}
				data, encodeErr := st.MarshalBinary()
				if encodeErr != nil {
					t.Fatal(encodeErr)
				}
				st, err = admission.UnmarshalScheduleState(data)
				if err != nil {
					t.Fatal(err)
				}
			}
			arrival := paid
			arrival.ID, arrival.Scope = "arrival", "new"
			byID[arrival.ID] = byID[paid.ID]
			lim.GeneralBytes, lim.ReservedBytes = 10000, 10000
			if lane == admission.LaneGeneral {
				lim.General = 1
			} else {
				lim.Reserved = 1
			}
			items := slotReady([]admission.ScheduleItem{paid, arrival}, byID, admission.NewSlotLimits(1, 1, nil))
			picks, _, err = admission.Schedule(items, st, lim)
			if err != nil || len(picks) != 1 || picks[0].ID != paid.ID || picks[0].Lane != lane {
				t.Fatalf("recovered slot lost the saved turn: %+v %v", picks, err)
			}
		})
	}
}

// Each ending, including a delayed result after the evictor was swept,
// ends a claim once. Restart, duplicate calls and expiry preserve totals.
func TestAdmissionLedgerEvictionEveryEnding(t *testing.T) {
	for _, ending := range []string{"failed", "applied", "lease", "existing", "settle-reserved", "settle-executing"} {
		for _, swept := range []bool{false, true} {
			t.Run(ending+map[bool]string{false: "/live", true: "/swept"}[swept], func(t *testing.T) {
				f := liveLedgerFixture(t)
				f.l.SetOccupants(&fullGeneral)
				low := f.verifiedWith("192.0.2.10", admission.SeverityWarning, 3*time.Hour)
				a := f.evicting("192.0.2.11", low)
				executed := ending != "settle-reserved"
				if executed {
					if _, _, _, err := f.l.Execute(a.Attempt.ID); err != nil {
						t.Fatal(err)
					}
				}
				if swept {
					f.tickAt(a.ExpiresAt)
				}
				beforeObserve := f.snapshot()
				if _, got, granted, err := f.l.Observe(a.Attempt.Candidate, a.Lane, a.ExpiresAt); err != nil || granted || got.Attempt.ID != a.Attempt.ID || !reflect.DeepEqual(beforeObserve, f.snapshot()) {
					t.Fatalf("observe readback changed a claim: %+v %v %v", got, granted, err)
				}
				if ending == "settle-reserved" || ending == "settle-executing" {
					l, err := OpenAdmissionLedger(f.db, f.reg)
					if err != nil {
						t.Fatal(err)
					}
					failed, unknown, err := l.Settle()
					if err != nil || failed+unknown != 1 || (unknown == 1) != executed {
						t.Fatalf("settle %d %d %v", failed, unknown, err)
					}
					if failed, unknown, err = l.Settle(); err != nil || failed != 0 || unknown != 0 {
						t.Fatalf("duplicate settle %d %d %v", failed, unknown, err)
					}
				} else {
					finish := func() error {
						var err error
						switch ending {
						case "lease":
							_, _, err = f.l.FinishOnLease(a.Attempt.ID, admission.DispositionApplied, time.Minute)
						case "existing":
							_, _, err = f.l.FinishExisting(a.Attempt.ID, admission.EffectLink{Effect: string(low.Attempt.ID), ExpiresAt: low.ExpiresAt})
						default:
							d := admission.DispositionFailed
							if ending == "applied" {
								d = admission.DispositionApplied
							}
							_, _, err = f.l.Finish(a.Attempt.ID, d)
						}
						return err
					}
					if err := finish(); err != nil {
						t.Fatal(err)
					}
					before := f.snapshot()
					if err := finish(); err != nil || !reflect.DeepEqual(before, f.snapshot()) {
						t.Fatalf("duplicate outcome changed the ledger: %v", err)
					}
				}
				victim, found := f.effectOf(low)
				verified := ending == "applied" || ending == "lease"
				unknown := ending == "settle-executing"
				if !found || victim.Evicted != verified || (victim.EvictedBy != "") != (verified || unknown) {
					t.Fatalf("claim not ended correctly: %+v", victim)
				}
				want := 1
				if unknown && !swept {
					want = 2
				} else if verified && swept {
					want = 0
				}
				if _, tally, _ := f.effectRecords(); tally != (admission.EffectTally{General: want}) {
					t.Fatalf("tally %+v, want %d", tally, want)
				}
				if _, err := OpenAdmissionLedger(f.db, f.reg); err != nil {
					t.Fatalf("outcome cannot reopen: %v", err)
				}
				f.tickAt(low.ExpiresAt)
				if records, tally, _ := f.effectRecords(); len(records) != 0 || tally != (admission.EffectTally{}) {
					t.Fatalf("swept records %+v tally %+v", records, tally)
				}
			})
		}
	}
}

// A retained victim can outlive the unknown evictor, its retirement and
// its entire history. None of those events makes the victim reusable.
func TestAdmissionLedgerEvictionOutlivesRetiredHistory(t *testing.T) {
	f := liveLedgerFixture(t)
	f.l.SetOccupants(&fullGeneral)
	low := f.verifiedWith("192.0.2.10", admission.SeverityWarning, 40*24*time.Hour)
	a := f.evicting("192.0.2.11", low)
	if _, _, _, err := f.l.Execute(a.Attempt.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.l.Finish(a.Attempt.ID, admission.DispositionUnknown); err != nil {
		t.Fatal(err)
	}
	f.ackAll()
	f.tickAt(a.ExpiresAt)
	if _, _, granted, err := f.l.RetireUnproven(a.Attempt.ID); err != nil || !granted {
		t.Fatalf("retire %v %v", granted, err)
	}
	before := f.snapshot()
	if _, _, granted, err := f.l.RetireUnproven(a.Attempt.ID); err != nil || granted || !reflect.DeepEqual(before, f.snapshot()) {
		t.Fatalf("duplicate retirement %v %v", granted, err)
	}
	if _, err := OpenAdmissionLedger(f.db, f.reg); err != nil {
		t.Fatalf("retired unknown cannot reopen: %v", err)
	}
	f.ackAll()
	f.tickAt(f.wall.Add(31 * 24 * time.Hour))
	if _, err := f.l.Attempt(a.Attempt.ID); err == nil {
		t.Fatalf("evictor history did not retire: %v", err)
	}
	victim, found := f.effectOf(low)
	if !found || victim.EvictedBy != a.Attempt.ID || victim.Evicted || !victim.Holds() {
		t.Fatalf("retirement released the victim: %+v", victim)
	}
	if _, tally, _ := f.effectRecords(); tally != (admission.EffectTally{General: 1}) {
		t.Fatalf("retirement tally %+v", tally)
	}
	if _, err := OpenAdmissionLedger(f.db, f.reg); err != nil {
		t.Fatalf("retired claim cannot reopen: %v", err)
	}
	f.tickAt(low.ExpiresAt)
	if records, tally, _ := f.effectRecords(); len(records) != 0 || tally != (admission.EffectTally{}) {
		t.Fatalf("final sweep %+v %+v", records, tally)
	}
}

// Re-encoded corrupt intents must fail both directions of the proof,
// including after either record's expiry sweep.
func TestAdmissionLedgerEvictionIntentProofBothDirections(t *testing.T) {
	for _, damage := range []string{"omit", "target", "invent"} {
		for _, sweep := range []string{"none", "victim", "evictor"} {
			t.Run(damage+"/"+sweep, func(t *testing.T) {
				f := liveLedgerFixture(t)
				f.l.SetOccupants(&fullGeneral)
				ttl := time.Hour
				if sweep == "evictor" {
					ttl = 3 * time.Hour
				}
				low := f.verifiedWith("192.0.2.10", admission.SeverityWarning, ttl)
				a := f.evicting("192.0.2.11", low)
				ins, _, err := f.l.ExecuteBatch([]admission.ActionID{a.Attempt.ID})
				if err != nil {
					t.Fatal(err)
				}
				switch sweep {
				case "victim":
					f.tickAt(low.ExpiresAt)
				case "evictor":
					f.tickAt(a.ExpiresAt)
				}
				if _, err = OpenAdmissionLedger(f.db, f.reg); err != nil {
					t.Fatalf("reachable state rejected: %v", err)
				}
				in := ins[0]
				switch damage {
				case "omit":
					in.Victim = admission.Victim{}
				case "target":
					in.Victim.Target = f.target("192.0.2.99")
				case "invent":
					in.Victim.Action = "act_00000000000000000000000000000009"
				}
				data, err := in.MarshalBinary()
				if err != nil {
					t.Fatal(err)
				}
				if err = f.db.bolt.Update(func(tx *bolt.Tx) error {
					return tx.Bucket([]byte(admissionIntentsBucket)).Put([]byte(a.Attempt.ID), data)
				}); err != nil {
					t.Fatal(err)
				}
				if _, err = OpenAdmissionLedger(f.db, f.reg); !isCorrupt(err) {
					t.Fatalf("one-sided intent accepted: %v", err)
				}
			})
		}
	}
}

// Unknown v2 intents pin the declared bound, not their current encoded
// length or the old bound. Open must prove the same stored total.
func TestAdmissionLedgerEvictionRecoveryBound(t *testing.T) {
	f := liveLedgerFixture(t)
	f.l.SetOccupants(&fullGeneral)
	low := f.verifiedWith("192.0.2.10", admission.SeverityWarning, time.Hour)
	a := f.evicting("192.0.2.11", low)
	if _, _, _, err := f.l.Execute(a.Attempt.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.l.Finish(a.Attempt.ID, admission.DispositionUnknown); err != nil {
		t.Fatal(err)
	}
	h, found := f.historyEntry(a.Attempt.Candidate)
	if !found || !h.Pinned || f.storageState().Recovery != uint64(h.Charged())+384 {
		t.Fatalf("unknown intent recovery: %+v %+v", h, f.storageState())
	}
	if _, err := OpenAdmissionLedger(f.db, f.reg); err != nil {
		t.Fatal(err)
	}
	f.adjustStorage(func(s *admission.StorageState) { s.Recovery -= 384 - 256 })
	if _, err := OpenAdmissionLedger(f.db, f.reg); !isCorrupt(err) {
		t.Fatalf("old recovery bound accepted: %v", err)
	}
}

// Losing either side before its own expiry is not an expiry sweep, even
// if the stored tally is changed to hide the missing slot.
func TestAdmissionLedgerEvictionMissingLiveRecordIsCorrupt(t *testing.T) {
	for _, side := range []string{"member", "victim"} {
		t.Run(side, func(t *testing.T) {
			f := liveLedgerFixture(t)
			f.l.SetOccupants(&fullGeneral)
			low := f.verifiedWith("192.0.2.10", admission.SeverityWarning, time.Hour)
			a := f.evicting("192.0.2.11", low)
			rec, _ := f.effectOf(a)
			if side == "victim" {
				rec, _ = f.effectOf(low)
			}
			if err := f.db.bolt.Update(func(tx *bolt.Tx) error {
				key, err := rec.Key()
				if err != nil {
					return err
				}
				return deleteEffect(tx, key, rec)
			}); err != nil {
				t.Fatal(err)
			}
			if _, err := OpenAdmissionLedger(f.db, f.reg); !isCorrupt(err) {
				t.Fatalf("missing live %s accepted: %v", side, err)
			}
		})
	}
}

// An intent can precede the victim's expiry sweep. Every ending must
// accept that missing victim without dropping the surviving member slot.
func TestAdmissionLedgerEvictionVictimSweptAfterExecution(t *testing.T) {
	for _, d := range []admission.Disposition{admission.DispositionApplied, admission.DispositionFailed, admission.DispositionUnknown} {
		t.Run(d.String(), func(t *testing.T) {
			f := liveLedgerFixture(t)
			f.l.SetOccupants(&fullGeneral)
			low := f.verifiedWith("192.0.2.10", admission.SeverityWarning, time.Minute)
			a := f.evicting("192.0.2.11", low)
			if _, _, _, err := f.l.Execute(a.Attempt.ID); err != nil {
				t.Fatal(err)
			}
			f.tickAt(low.ExpiresAt)
			if _, err := OpenAdmissionLedger(f.db, f.reg); err != nil {
				t.Fatalf("swept victim before outcome: %v", err)
			}
			if _, _, err := f.l.Finish(a.Attempt.ID, d); err != nil {
				t.Fatalf("missing expired victim blocked %s: %v", d, err)
			}
			before := f.snapshot()
			if _, _, err := f.l.Finish(a.Attempt.ID, d); err != nil || !reflect.DeepEqual(before, f.snapshot()) {
				t.Fatalf("duplicate %s changed the ledger: %v", d, err)
			}
			want := 1
			if d == admission.DispositionFailed {
				want = 0
			}
			if records, tally, _ := f.effectRecords(); len(records) != want || tally != (admission.EffectTally{General: want}) {
				t.Fatalf("remaining records %+v tally %+v, want %d", records, tally, want)
			}
			if _, err := OpenAdmissionLedger(f.db, f.reg); err != nil {
				t.Fatalf("swept victim after outcome: %v", err)
			}
			f.tickAt(a.ExpiresAt)
			if records, tally, _ := f.effectRecords(); len(records) != 0 || tally != (admission.EffectTally{}) {
				t.Fatalf("both swept: %+v %+v", records, tally)
			}
		})
	}
}

// A new generation for an address already blocked never claims that
// block as its victim: it waits for a slot, and the ledger still opens.
func TestAdmissionLedgerEvictionSkipsTheSameAddress(t *testing.T) {
	f := liveLedgerFixture(t)
	f.l.SetOccupants(&fullGeneral)
	low := f.verifiedWith("192.0.2.10", admission.SeverityWarning, time.Hour)
	root := f.published(evidenceSpec{target: "192.0.2.10", cursor: "evict-again", severity: admission.SeverityCritical})
	req := f.request("192.0.2.10", root)
	req.Generation++
	_, again := f.enqueue(req)
	_, _, _, err := f.l.Reserve(again, admission.LaneGeneral, f.wall.Add(2*time.Hour))
	wantLedgerReason(t, "the same address", err, admission.ReasonSetFull)
	if victim, _ := f.effectOf(low); victim.EvictedBy != "" {
		t.Fatalf("victim record %+v claimed by its own address", victim)
	}
	if _, err = OpenAdmissionLedger(f.db, f.reg); err != nil {
		t.Fatal(err)
	}
}
