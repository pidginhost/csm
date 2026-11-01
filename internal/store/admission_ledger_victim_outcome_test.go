package store

import (
	"fmt"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
)

// victimOutcomes is what a verified block's attempt can report about the
// victim it claimed, with the records and tally each leaves.
var victimOutcomes = []struct {
	outcome admission.VictimOutcome
	evicted bool
	tally   admission.EffectTally
}{
	{admission.VictimRemoved, true, admission.EffectTally{General: 1}},
	{admission.VictimSpared, false, admission.EffectTally{General: 2}},
}

// The applier reports what a verified block did to its victim. A removal
// it proved evicts the victim; a victim it never removed returns to the
// pool with its slot. Either way the block keeps no claim.
func TestAdmissionLedgerFinishEvictionOutcomes(t *testing.T) {
	for _, tc := range victimOutcomes {
		f := liveLedgerFixture(t)
		f.l.SetOccupants(&fullGeneral)
		low := f.verifiedWith("192.0.2.10", admission.SeverityWarning, 3*time.Hour)
		a := f.evicting("192.0.2.11", low)
		if _, _, _, err := f.l.Execute(a.Attempt.ID); err != nil {
			t.Fatal(err)
		}
		if _, _, err := f.l.FinishEviction(a.Attempt.ID, admission.DispositionApplied, tc.outcome, 0); err != nil {
			t.Fatalf("%v: %v", tc.outcome, err)
		}
		member, _ := f.effectOf(a)
		victim, found := f.effectOf(low)
		if !found || !member.Verified() || member.Victim != (admission.EffectRef{}) || victim.Evicted != tc.evicted || (victim.EvictedBy != "") != tc.evicted {
			t.Fatalf("%v: member %+v victim %+v", tc.outcome, member, victim)
		}
		if _, tally, _ := f.effectRecords(); tally != tc.tally {
			t.Fatalf("%v: tally %+v, want %+v", tc.outcome, tally, tc.tally)
		}
		if _, err := OpenAdmissionLedger(f.db, f.reg); err != nil {
			t.Fatalf("%v: reopen: %v", tc.outcome, err)
		}
	}
}

// A block whose own record was swept before its definite outcome still
// reports what it did to its victim through the intent.
func TestAdmissionLedgerFinishEvictionAfterTheBlocksSweep(t *testing.T) {
	for _, tc := range victimOutcomes {
		f := liveLedgerFixture(t)
		f.l.SetOccupants(&fullGeneral)
		low := f.verifiedWith("192.0.2.10", admission.SeverityWarning, 3*time.Hour)
		a := f.evicting("192.0.2.11", low)
		if _, _, _, err := f.l.Execute(a.Attempt.ID); err != nil {
			t.Fatal(err)
		}
		f.tickAt(a.ExpiresAt)
		if _, found := f.effectOf(a); found {
			t.Fatal("the block's record outlived its expiry")
		}
		if _, _, err := f.l.FinishEviction(a.Attempt.ID, admission.DispositionApplied, tc.outcome, 0); err != nil {
			t.Fatalf("%v: %v", tc.outcome, err)
		}
		victim, _ := f.effectOf(low)
		if victim.Evicted != tc.evicted || (victim.EvictedBy != "") != tc.evicted {
			t.Fatalf("%v: victim %+v", tc.outcome, victim)
		}
		want := tc.tally
		want.General--
		if _, tally, _ := f.effectRecords(); tally != want {
			t.Fatalf("%v: tally %+v, want %+v", tc.outcome, tally, want)
		}
		if _, err := OpenAdmissionLedger(f.db, f.reg); err != nil {
			t.Fatalf("%v: reopen: %v", tc.outcome, err)
		}
	}
}

// An outcome the applier cannot report, or a verified block whose removal
// is unproven, is refused before anything changes: an unproven removal
// is an unknown outcome.
func TestAdmissionLedgerFinishEvictionRefusesAnImpossibleOutcome(t *testing.T) {
	for _, tc := range []struct {
		d admission.Disposition
		v admission.VictimOutcome
	}{
		{admission.DispositionApplied, 0},
		{admission.DispositionApplied, admission.VictimUnproven},
		{admission.DispositionNarrowed, admission.VictimUnproven},
	} {
		f := liveLedgerFixture(t)
		f.l.SetOccupants(&fullGeneral)
		low := f.verifiedWith("192.0.2.10", admission.SeverityWarning, 3*time.Hour)
		a := f.evicting("192.0.2.11", low)
		if _, _, _, err := f.l.Execute(a.Attempt.ID); err != nil {
			t.Fatal(err)
		}
		_, _, err := f.l.FinishEviction(a.Attempt.ID, tc.d, tc.v, 0)
		wantLedgerReason(t, "an impossible victim outcome", err, admission.ReasonInvalid)
		if att, _ := f.l.Attempt(a.Attempt.ID); att.State != admission.StateExecuting {
			t.Fatalf("%v/%v: attempt %+v changed", tc.d, tc.v, att)
		}
	}
}

// An unknown outcome keeps the claim whatever the applier saw of the
// victim: raw absence is no committed eviction.
func TestAdmissionLedgerUnknownEvictionIgnoresTheVictimOutcome(t *testing.T) {
	for _, v := range []admission.VictimOutcome{admission.VictimRemoved, admission.VictimSpared, admission.VictimUnproven} {
		f := liveLedgerFixture(t)
		f.l.SetOccupants(&fullGeneral)
		low := f.verifiedWith("192.0.2.10", admission.SeverityWarning, 3*time.Hour)
		a := f.evicting("192.0.2.11", low)
		if _, _, _, err := f.l.Execute(a.Attempt.ID); err != nil {
			t.Fatal(err)
		}
		if _, _, err := f.l.FinishEviction(a.Attempt.ID, admission.DispositionUnknown, v, 0); err != nil {
			t.Fatalf("%v: %v", v, err)
		}
		if victim, _ := f.effectOf(low); victim.EvictedBy != a.Attempt.ID || victim.Evicted {
			t.Fatalf("%v: victim %+v", v, victim)
		}
		if _, tally, _ := f.effectRecords(); tally != (admission.EffectTally{General: 2}) {
			t.Fatalf("%v: tally %+v", v, tally)
		}
		if _, err := OpenAdmissionLedger(f.db, f.reg); err != nil {
			t.Fatalf("%v: reopen: %v", v, err)
		}
		ids := []string{string(low.Attempt.ID), string(a.Attempt.ID)}
		unproven, err := ReadUnprovenBlockActions(f.db, ids)
		if err != nil || len(unproven) != 1 || unproven[0] != ids[1] {
			t.Fatalf("%v: unproven %v, %v; want only the member", v, unproven, err)
		}
		settled, err := ReadSettledBlockActions(f.db, ids)
		if err != nil || len(settled) != 0 {
			t.Fatalf("%v: settled %v, %v; neither row may be removed", v, settled, err)
		}
	}
}

// Startup holds back and then removes the row of a victim whose eviction
// the ledger verified: its element is gone and the firewall must not
// restore it. A spared or unproven victim keeps its row.
func TestReadSettledBlockActionsIncludesEvictedVictims(t *testing.T) {
	for _, tc := range victimOutcomes {
		f := liveLedgerFixture(t)
		f.l.SetOccupants(&fullGeneral)
		low := f.verifiedWith("192.0.2.10", admission.SeverityWarning, 3*time.Hour)
		a := f.evicting("192.0.2.11", low)
		if _, _, _, err := f.l.Execute(a.Attempt.ID); err != nil {
			t.Fatal(err)
		}
		if _, _, err := f.l.FinishEviction(a.Attempt.ID, admission.DispositionApplied, tc.outcome, 0); err != nil {
			t.Fatal(err)
		}
		ids := []string{string(low.Attempt.ID), string(a.Attempt.ID)}
		settled, err := ReadSettledBlockActions(f.db, ids)
		if err != nil {
			t.Fatal(err)
		}
		if got := len(settled) == 1 && settled[0] == ids[0]; got != tc.evicted || (!tc.evicted && len(settled) != 0) {
			t.Fatalf("%v: settled %v", tc.outcome, settled)
		}
		unproven, err := ReadUnprovenBlockActions(f.db, ids)
		if err != nil || fmt.Sprint(unproven) != fmt.Sprint(settled) {
			t.Fatalf("%v: unproven %v %v, want %v", tc.outcome, unproven, err, settled)
		}
	}
}
