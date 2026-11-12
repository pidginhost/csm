package store

import (
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
)

// A requester over its share rotates only its own blocks: while they are
// younger than the hold it waits, though another scope's block is older,
// and nothing is charged or claimed. Once its own hold passes, its own
// oldest block goes (equal-tier sets and rotation).
func TestAdmissionLedgerYoungOwnBlocksWaitForTheirHold(t *testing.T) {
	f := liveLedgerFixture(t)
	f.fillGeneral(3)
	bobs := f.verifiedBy("192.0.2.20", admission.SeverityHigh, f.owner("bob"), 4*time.Hour)
	f.tickAt(f.wall.Add(admission.RotationHold))
	first := f.verifiedBy("192.0.2.10", admission.SeverityHigh, f.owner("alice"), 4*time.Hour)
	f.tickAt(f.wall.Add(time.Minute))
	f.verifiedBy("192.0.2.11", admission.SeverityHigh, f.owner("alice"), 4*time.Hour)
	f.begin()
	id := f.freshWith("192.0.2.12", admission.SeverityHigh, f.owner("alice"))
	before, charged := f.snapshot(), f.ceilingState()
	_, _, _, err := f.l.Reserve(id, admission.LaneGeneral, f.wall.Add(time.Hour))
	wantLedgerReason(t, "young own blocks", err, admission.ReasonSetFull)
	if !reflect.DeepEqual(before, f.snapshot()) || f.ceilingState() != charged || f.capacityNotices(admission.ReasonSetFull) != 0 {
		t.Fatal("a refused rotation changed the ledger")
	}
	if r, _ := f.effectOf(bobs); r.EvictedBy != "" {
		t.Fatalf("another scope's older block was claimed: %+v", r)
	}
	f.tickAt(f.wall.Add(admission.RotationHold - time.Minute))
	_, a, _, err := f.l.Reserve(id, admission.LaneGeneral, f.wall.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if member, _ := f.effectOf(a); member.Victim.Action != first.Attempt.ID {
		t.Fatalf("member record %+v, want its own oldest block %s", member, first.Attempt.ID)
	}
}

// Without pressure nothing rotates: fresh work of the same tier takes the
// free slot and an old block keeps its record and expiry untouched.
func TestAdmissionLedgerFreeSlotKeepsAnOldBlock(t *testing.T) {
	f := liveLedgerFixture(t)
	f.fillGeneral(2)
	old := f.verifiedBy("192.0.2.10", admission.SeverityHigh, f.owner("alice"), 4*time.Hour)
	f.tickAt(f.wall.Add(admission.RotationHold + time.Minute))
	original, found := f.effectOf(old)
	if !found || !original.Verified() || !original.Holds() {
		t.Fatalf("the old block holds no verified effect: %+v", original)
	}
	f.begin()
	id := f.freshWith("192.0.2.11", admission.SeverityHigh, f.owner("alice"))
	charged := f.ceilingState()
	_, a, granted, err := f.l.Reserve(id, admission.LaneGeneral, f.wall.Add(time.Hour))
	if err != nil || !granted {
		t.Fatalf("free-slot reservation: granted %v, error %v", granted, err)
	}
	if member, found := f.effectOf(a); !found || !member.Holds() || member.Partition != admission.PartitionGeneral || member.Victim != (admission.EffectRef{}) {
		t.Fatalf("free-slot reservation did not hold a general slot without a victim: %+v", member)
	}
	if _, tally, _ := f.effectRecords(); tally != (admission.EffectTally{General: 2}) || f.ceilingState().General.Used != charged.General.Used+1 || f.ceilingState().Reserved != charged.Reserved {
		t.Fatalf("free-slot reservation: tally %+v, ceiling %+v, before %+v", tally, f.ceilingState(), charged)
	}
	if kept, _ := f.effectOf(old); kept != original || f.capacityNotices(admission.ReasonSetFull) != 0 {
		t.Fatalf("old block %+v, want %+v unchanged and no notice", kept, original)
	}
}

// A block rotated out returns in its episode as a charged re-admission
// with no rotation privilege: not fresh, so it waits for a free slot even
// once the block that replaced it is past its hold, and its episode keeps
// its boundary.
func TestAdmissionLedgerRotatedBlockReturnsWithoutRotating(t *testing.T) {
	f, victim := rotationFixture(t)
	f.tickAt(f.wall.Add(admission.RotationHold))
	rot := f.freshWith("192.0.2.11", admission.SeverityHigh, f.owner("alice"))
	_, a, _, err := f.l.Reserve(rot, admission.LaneGeneral, f.wall.Add(4*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err = f.l.Execute(a.Attempt.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err = f.l.FinishEviction(a.Attempt.ID, admission.DispositionApplied, admission.VictimRemoved, 0); err != nil {
		t.Fatal(err)
	}
	episode, _ := f.episodeAt("192.0.2.10")
	f.tickAt(f.wall.Add(time.Second))
	r := f.arrive(f.arrival(evidenceSpec{target: "192.0.2.10", cursor: "return", owner: f.owner("alice")}))[0]
	if r.Err != nil || !r.Created {
		t.Fatalf("return %+v", r)
	}
	back := f.candidateOf(r.Candidate)
	if back.Key.Episode != f.candidateOf(victim.Attempt.Candidate).Key.Episode || back.Key.Generation != 2 {
		t.Fatalf("return %+v is not the same episode's next generation", back.Key)
	}
	f.tickAt(f.wall.Add(admission.RotationHold))
	if fresh, ferr := f.l.Fresh(back); ferr != nil || fresh {
		t.Fatalf("a re-admission is fresh: %v %v", fresh, ferr)
	}
	before := f.snapshot()
	_, _, _, err = f.l.Reserve(r.Candidate, admission.LaneGeneral, f.wall.Add(time.Hour))
	wantLedgerReason(t, "a re-admission against an old equal-tier block", err, admission.ReasonSetFull)
	if !reflect.DeepEqual(before, f.snapshot()) {
		t.Fatal("a refused re-admission changed the ledger")
	}
	if now, _ := f.episodeAt("192.0.2.10"); now.Verified != episode.Verified || now.EndElapsed != episode.EndElapsed {
		t.Fatalf("episode boundary %v/%v moved from %v/%v", now.Verified, now.EndElapsed, episode.Verified, episode.EndElapsed)
	}
}

// Rotations are charged reservations, so a flood of fresh claimants
// rotates no more blocks than the general lane's credit and refill allow:
// floor(B + G*d/3600) over d seconds (quantitative victim bound).
func TestAdmissionLedgerRotationsStayWithinTheCeiling(t *testing.T) {
	for _, d := range []int{440, 450} {
		t.Run(fmt.Sprint(d), func(t *testing.T) {
			f := liveLedgerFixture(t)
			if err := f.l.SetCeiling(10); err != nil {
				t.Fatal(err)
			}
			f.fillGeneral(4)
			var olds []admission.AttemptRecord
			for _, addr := range []string{"192.0.2.20", "192.0.2.21", "192.0.2.22", "192.0.2.23"} {
				f.leaveCeilingCredit(1, 0)
				olds = append(olds, f.verifiedBy(addr, admission.SeverityHigh, f.owner("bob"), 8*time.Hour))
			}
			f.tickAt(f.wall.Add(admission.RotationHold))
			f.leaveCeilingCredit(1, 0)
			start := f.ceilingState()
			f.begin()
			for _, addr := range []string{"192.0.2.10", "192.0.2.11", "192.0.2.12", "192.0.2.13"} {
				f.freshWith(addr, admission.SeverityHigh, f.owner("alice"))
			}
			// Shares let alice reclaim two of bob's four blocks; the ceiling's one
			// saved unit permits one rotation before refill, two at its boundary.
			general, _ := admission.CeilingLanes(10)
			chargedRotations := 0
			for s := 0; s <= d; s += 10 {
				if s > 0 {
					f.tickAt(f.wall.Add(10 * time.Second))
				}
				for _, p := range f.schedule(allSlots) {
					_, a, _, err := f.l.Reserve(p.ID, p.Lane, f.wall.Add(time.Hour))
					if err != nil {
						t.Fatalf("scheduled rotation was refused: %v", err)
					}
					if got := f.ceilingState().General.Used; got != start.General.Used+uint32(chargedRotations+1) {
						t.Fatalf("rotation was not charged: used=%d, before=%d", got, start.General.Used)
					}
					chargedRotations++
					if _, _, _, err = f.l.Execute(a.Attempt.ID); err != nil {
						t.Fatal(err)
					}
					if _, _, err = f.l.FinishEviction(a.Attempt.ID, admission.DispositionApplied, admission.VictimRemoved, 0); err != nil {
						t.Fatal(err)
					}
				}
			}
			rotated := 0
			for _, o := range olds {
				if r, _ := f.effectOf(o); r.Evicted {
					rotated++
				}
			}
			bound := 1 + int(general)*d/3600
			used := int(f.ceilingState().General.Used - start.General.Used)
			if want := map[int]int{440: 1, 450: 2}[d]; bound != want || rotated != want || used != rotated {
				t.Fatalf("rotated %d, charged %d, bound %d", rotated, used, bound)
			}
		})
	}
}

// A set filled by operator entries leaves Critical direct work queued and
// visible: no charge, no effect record, one capacity notice.
func TestAdmissionLedgerOperatorFilledSetLeavesCriticalWorkVisible(t *testing.T) {
	f := liveLedgerFixture(t)
	f.l.SetOccupants(&admission.SetOccupancy{Limit: 5, Unclaimed: 5})
	f.begin()
	id := f.directArrivals("192.0.2.10")[0]
	charged := f.ceilingState()
	if picks := f.schedule(fullSchedule); len(picks) != 0 {
		t.Fatalf("an operator-filled set served %+v", picks)
	}
	if c := f.candidateOf(id); c.State != admission.StateQueued || c.Reason != admission.ReasonSetFull {
		t.Fatalf("critical work %+v, want queued for set_full", c)
	}
	if records, tally, _ := f.effectRecords(); len(records) != 0 || tally != (admission.EffectTally{}) || f.ceilingState() != charged {
		t.Fatalf("records %v, tally %+v, ceiling %+v", records, tally, f.ceilingState())
	}
	if n := f.capacityNotices(admission.ReasonSetFull); n != 1 {
		t.Fatalf("capacity notices %d, want 1", n)
	}
}

// A lowered limit that leaves the general partition overfull admits no
// rotation, though its blocks are past their hold; a raised one gives fresh
// work the free slot first (an overfull partition admits nothing
// until the proposed state fits).
func TestAdmissionLedgerOverfullPartitionNeverRotates(t *testing.T) {
	f := liveLedgerFixture(t)
	f.fillGeneral(2)
	first := f.verifiedBy("192.0.2.10", admission.SeverityHigh, f.owner("alice"), 4*time.Hour)
	second := f.verifiedBy("192.0.2.11", admission.SeverityHigh, f.owner("alice"), 4*time.Hour)
	f.tickAt(f.wall.Add(admission.RotationHold))
	kept := map[admission.ActionID]admission.EffectRecord{}
	for _, a := range []admission.AttemptRecord{first, second} {
		r, found := f.effectOf(a)
		if !found || !r.Verified() || !r.Holds() {
			t.Fatalf("the old block holds no verified effect: %+v", r)
		}
		kept[a.Attempt.ID] = r
	}
	f.begin()
	id := f.freshWith("192.0.2.12", admission.SeverityHigh, f.owner("alice"))
	// One general slot for two general blocks.
	f.l.SetOccupants(&admission.SetOccupancy{Limit: 5, Unclaimed: 3})
	before, charged := f.snapshot(), f.ceilingState()
	_, _, _, err := f.l.Reserve(id, admission.LaneGeneral, f.wall.Add(time.Hour))
	wantLedgerReason(t, "overfull partition", err, admission.ReasonSetFull)
	if !reflect.DeepEqual(before, f.snapshot()) || f.ceilingState() != charged {
		t.Fatal("a refused reservation changed the ledger")
	}
	f.l.SetOccupants(&admission.SetOccupancy{Limit: 7, Unclaimed: 3})
	_, a, granted, err := f.l.Reserve(id, admission.LaneGeneral, f.wall.Add(time.Hour))
	if err != nil || !granted {
		t.Fatalf("raised-limit reservation: granted %v, error %v", granted, err)
	}
	if member, found := f.effectOf(a); !found || !member.Holds() || member.Partition != admission.PartitionGeneral || member.Victim != (admission.EffectRef{}) {
		t.Fatalf("raised-limit reservation did not hold a general slot without a victim: %+v", member)
	}
	if _, tally, _ := f.effectRecords(); tally != (admission.EffectTally{General: 3}) || f.ceilingState().General.Used != charged.General.Used+1 || f.ceilingState().Reserved != charged.Reserved {
		t.Fatalf("raised-limit reservation: tally %+v, ceiling %+v, before %+v", tally, f.ceilingState(), charged)
	}
	for _, old := range []admission.AttemptRecord{first, second} {
		if r, _ := f.effectOf(old); r != kept[old.Attempt.ID] {
			t.Fatalf("old block %+v, want %+v", r, kept[old.Attempt.ID])
		}
	}
}

// The remainder cursor moves on every cycle under pressure,
// including cycles where every victim is still held: a zero-share
// claimant's turn alternates with the holder's while it waits, and it
// reclaims on the first cycle after the hold that gives it the remainder.
// The cursor names the scope that took the remainder last.
func TestAdmissionLedgerRemainderMovesWhileVictimsAreHeld(t *testing.T) {
	f := liveLedgerFixture(t)
	f.l.SetOccupants(&fullGeneral)
	bobs := f.verifiedBy("192.0.2.20", admission.SeverityHigh, f.owner("bob"), 4*time.Hour)
	f.begin()
	id := f.freshWith("192.0.2.11", admission.SeverityHigh, f.owner("alice"))
	alice := f.candidateOf(id).Scope.Key()
	bob, _ := f.effectOf(bobs)
	var cursors []string
	for range 4 {
		if picks := f.schedule(allSlots); len(picks) != 0 {
			t.Fatalf("a held victim was rotated: %+v", picks)
		}
		cursors = append(cursors, f.queueState().SetCursors.General)
	}
	if want := []string{alice, bob.Scope, alice, bob.Scope}; !reflect.DeepEqual(cursors, want) {
		t.Fatalf("cursors while held %v, want %v", cursors, want)
	}
	// The hold passes on a cycle that gives bob the remainder: alice waits
	// one more cycle.
	f.tickAt(f.wall.Add(admission.RotationHold))
	if picks := f.schedule(allSlots); len(picks) != 0 {
		t.Fatalf("a zero-share claimant reclaimed off its turn: %+v", picks)
	}
	if picks := f.schedule(allSlots); len(picks) != 1 || picks[0].ID != id {
		t.Fatalf("the claimant's remainder cycle picked %+v", picks)
	}
}

// More scopes than slots retain their turns and holds across restart.
// Two waiting scopes reclaim the two old borrowed slots within S cycles;
// no new hold is granted to a restored victim and no young replacement
// becomes a second victim in that wave.
func TestAdmissionLedgerManyScopesRotateAfterRestart(t *testing.T) {
	f := liveLedgerFixture(t)
	f.fillGeneral(2)
	olds := []admission.AttemptRecord{
		f.verifiedBy("192.0.2.20", admission.SeverityHigh, f.owner("bob"), 4*time.Hour),
		f.verifiedBy("192.0.2.21", admission.SeverityHigh, f.owner("bob"), 4*time.Hour),
	}
	f.begin()
	ids := []admission.CandidateID{
		f.freshWith("192.0.2.10", admission.SeverityHigh, f.owner("alice")),
		f.freshWith("192.0.2.11", admission.SeverityHigh, admission.Owner{}),
	}
	original := map[admission.ActionID]admission.EffectRecord{}
	for _, a := range olds {
		original[a.Attempt.ID], _ = f.effectOf(a)
	}
	f.tickAt(f.wall.Add(admission.RotationHold - time.Second))
	if picks := f.schedule(allSlots); len(picks) != 0 {
		t.Fatalf("young victims offered before restart: %+v", picks)
	}
	cursors := f.queueState().SetCursors
	f.reopen()
	f.fillGeneral(2)
	if got := f.queueState().SetCursors; got != cursors {
		t.Fatalf("restart reset set cursors: %+v, before %+v", got, cursors)
	}
	for _, a := range olds {
		if r, _ := f.effectOf(a); r != original[a.Attempt.ID] {
			t.Fatalf("restart changed a victim's hold or lease: %+v", r)
		}
	}
	f.tickAt(f.wall.Add(time.Second))
	charged := f.ceilingState()
	served := map[admission.CandidateID]bool{}
	for cycle := 0; cycle < 3 && len(served) < len(ids); cycle++ {
		for _, pick := range f.schedule(allSlots) {
			if served[pick.ID] || (pick.ID != ids[0] && pick.ID != ids[1]) {
				t.Fatalf("unexpected repeat or scope: %+v", pick)
			}
			_, a, _, err := f.l.Reserve(pick.ID, pick.Lane, f.wall.Add(time.Hour))
			if err != nil {
				t.Fatal(err)
			}
			r, ok := f.effectOf(a)
			if !ok || original[r.Victim.Action].Action == "" {
				t.Fatalf("claimant did not take an old borrowed victim: %+v", r)
			}
			if f.ceilingState().General.Used != charged.General.Used+uint32(len(served)+1) {
				t.Fatal("rotation was not charged")
			}
			if _, _, _, err = f.l.Execute(a.Attempt.ID); err != nil {
				t.Fatal(err)
			}
			if _, _, err = f.l.FinishEviction(a.Attempt.ID, admission.DispositionApplied, admission.VictimRemoved, 0); err != nil {
				t.Fatal(err)
			}
			if c := f.candidateOf(pick.ID); c.State != admission.StateVerified {
				t.Fatalf("claimant was not verified: %+v", c)
			}
			served[pick.ID] = true
		}
	}
	if len(served) != len(ids) {
		t.Fatalf("S=3 with two slots served %d of %d eligible claimants", len(served), len(ids))
	}
	for _, a := range olds {
		r, _ := f.effectOf(a)
		old := original[a.Attempt.ID]
		if !r.Evicted || r.Applied != old.Applied || r.Elapsed != old.Elapsed || r.ExpiresAt != old.ExpiresAt {
			t.Fatalf("rotation reset a victim's hold or lease: %+v, before %+v", r, old)
		}
	}
	if got := f.ceilingState(); got.General.Used != charged.General.Used+2 || got.Reserved != charged.Reserved {
		t.Fatalf("rotation refunded or crossed lanes: %+v, before %+v", got, charged)
	}
}
