package store

import (
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
)

// A C1 flood of one scope exhausts only the general lane. Another scope's
// direct and corroborated work takes the reserved lane one refilled unit
// at a time, direct first, and the flood can never reserve there. Only a
// verified outcome marks a block applied (spec 7.1, general ceiling and
// reserve).
func TestAdmissionLedgerFloodLeavesTheReserveToOtherScopes(t *testing.T) {
	f := liveLedgerFixture(t)
	alice, bob := f.owner("alice"), f.owner("bob")
	if err := f.l.SetCeiling(10); err != nil {
		t.Fatal(err)
	}
	flood := f.fill(30, evidenceSpec{producer: f.rep, check: "reputation", owner: bob})
	for _, id := range flood[:8] {
		if e, err := f.entry(id); err != nil || e.Tier.Class != admission.ClassC1 || e.Direct || e.Corroborated {
			t.Fatalf("fixture: flood must be general C1: %+v, %v", e, err)
		}
		f.leaveCeilingCredit(1, 0)
		if _, _, _, err := f.l.Reserve(id, admission.LaneGeneral, f.wall.Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
	}
	direct := f.published(evidenceSpec{producer: f.mail, check: "mail_takeover", target: "192.0.2.11", cursor: "direct", severity: admission.SeverityCritical, owner: alice})
	_, directID := f.enqueue(f.request("192.0.2.11", direct))
	local := f.published(evidenceSpec{target: "192.0.2.12", cursor: "local", owner: alice})
	rep := f.published(evidenceSpec{producer: f.rep, check: "reputation", target: "192.0.2.12", cursor: "rep", owner: alice})
	_, corrID := f.enqueue(f.request("192.0.2.12", local, rep))
	if e, err := f.entry(corrID); err != nil || !e.Corroborated || e.Direct {
		t.Fatalf("fixture: corroborated entry = %+v, %v", e, err)
	}
	f.leaveCeilingCredit(0, 1)
	start := f.ceilingState()
	if start.General.Used != 8 || start.Reserved.Used != 0 {
		t.Fatalf("C1 flood charges: %+v", start)
	}
	var attempts []admission.AttemptRecord
	for i, want := range []struct {
		id   admission.CandidateID
		lane admission.Lane
	}{{directID, admission.LaneDirect}, {corrID, admission.LaneCorroborated}} {
		picks := f.schedule(fullSchedule)
		if len(picks) != 1 || picks[0].ID != want.id || picks[0].Lane != want.lane {
			t.Fatalf("refill %d: picks = %+v, want %s on %s", i, picks, want.id, want.lane)
		}
		_, a, _, err := f.l.Reserve(picks[0].ID, picks[0].Lane, f.wall.Add(time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		attempts = append(attempts, a)
		f.leaveCeilingCredit(0, 1)
	}
	if s := f.ceilingState(); s.General.Used != start.General.Used || s.Reserved.Used != start.Reserved.Used+2 {
		t.Fatalf("lanes after two reserved turns = %+v, from %+v", s, start)
	}
	if err := f.l.SetCeiling(20); err != nil {
		t.Fatal(err)
	}
	f.leaveCeilingCredit(0, 1)
	before := f.snapshot()
	for _, lane := range []admission.Lane{admission.LaneDirect, admission.LaneCorroborated} {
		_, _, _, err := f.l.Reserve(flood[8], lane, f.wall.Add(time.Hour))
		wantLedgerErr(t, "flood work on "+lane.String(), err, admission.ErrLaneIneligible)
	}
	if picks := f.schedule(fullSchedule); len(picks) != 0 {
		t.Fatalf("the flood took a reserved turn: %+v", picks)
	}
	if !reflect.DeepEqual(before, f.snapshot()) {
		t.Fatal("a refused reservation changed the ledger")
	}
	for i, d := range []admission.Disposition{admission.DispositionApplied, admission.DispositionUnknown} {
		if _, _, _, err := f.l.Execute(attempts[i].Attempt.ID); err != nil {
			t.Fatal(err)
		}
		if _, _, err := f.l.Finish(attempts[i].Attempt.ID, d); err != nil {
			t.Fatal(err)
		}
		r, ok := f.effectOf(attempts[i])
		if !ok || r.Partition != admission.PartitionReserved || r.Applied.IsZero() != (d != admission.DispositionApplied) {
			t.Fatalf("%s: effect record %+v, %v", d, r, ok)
		}
	}
}

// Each reserved sub-lane serves all scopes once per cycle across restart.
// Only elapsed refill supplies later turns: no burst or empty schedule
// may spend a future scope turn. Every service has a charged effect.
func TestAdmissionLedgerReserveSaturationKeepsEveryScopeTurn(t *testing.T) {
	f := liveLedgerFixture(t)
	accounts := []string{"acct00", "acct01", "acct02", "acct03", "acct04"}
	f.refresh(accounts, nil)
	if err := f.l.SetCeiling(100); err != nil {
		t.Fatal(err)
	}
	for i, account := range accounts {
		for round := range 2 {
			for _, direct := range []bool{true, false} {
				addr := fmt.Sprintf("192.0.2.%d", 10+i*4+round*2)
				if direct {
					addr = fmt.Sprintf("192.0.2.%d", 11+i*4+round*2)
				}
				e := evidenceSpec{target: addr, cursor: addr, owner: f.owner(account)}
				if direct {
					e.producer, e.check, e.severity = f.mail, "mail_takeover", admission.SeverityCritical
				}
				roots := []admission.EvidenceID{f.published(e)}
				if !direct {
					e.producer, e.check, e.cursor = f.rep, "reputation", addr+"-rep"
					roots = append(roots, f.published(e))
				}
				f.enqueue(f.request(addr, roots[0], roots[1:]...))
			}
		}
	}
	f.leaveCeilingCredit(0, 1)
	lim := admission.ScheduleLimits{Reserved: 1, Members: 1}
	orders := map[admission.Lane][]string{}
	for turn := 0; turn < 4*len(accounts); turn++ {
		if turn > 0 {
			f.tickAt(f.wall.Add(3 * time.Minute))
		}
		if turn == 2*len(accounts) {
			state := f.snapshot()["adm:qstate:schedule"]
			f.reopen()
			if after := f.snapshot()["adm:qstate:schedule"]; state == "" || after != state {
				t.Fatal("restart lost reserved scheduler state")
			}
		}
		picks := f.schedule(lim)
		lane := admission.LaneDirect
		if turn%2 != 0 {
			lane = admission.LaneCorroborated
		}
		if len(picks) != 1 || picks[0].Lane != lane {
			t.Fatalf("reserved opportunity %d: picks %+v, want %s", turn, picks, lane)
		}
		pick := picks[0]
		orders[lane] = append(orders[lane], f.scopeOf(pick.ID))
		_, a, _, err := f.l.Reserve(pick.ID, lane, f.wall.Add(time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		if _, _, _, err = f.l.Execute(a.Attempt.ID); err != nil {
			t.Fatal(err)
		}
		if _, _, err = f.l.Finish(a.Attempt.ID, admission.DispositionApplied); err != nil {
			t.Fatal(err)
		}
		if r, ok := f.effectOf(a); !ok || r.Applied.IsZero() || r.Partition != admission.PartitionReserved || f.candidateOf(pick.ID).State != admission.StateVerified {
			t.Fatalf("reserved service lacks verified effect: %+v, %v", r, ok)
		}
		if c := f.ceilingState(); c.General.Used != 0 || c.Reserved.Used != uint32(turn+1) {
			t.Fatalf("reserved service charges %+v, turn %d", c, turn)
		}
		state := f.snapshot()["adm:qstate:schedule"]
		if picks := f.schedule(lim); len(picks) != 0 {
			t.Fatalf("a burst borrowed a future reserved opportunity: %+v", picks)
		}
		if after := f.snapshot()["adm:qstate:schedule"]; after != state {
			t.Fatal("an unfunded turn spent a future reserved cursor")
		}
	}
	for lane, order := range orders {
		for start := 0; start+len(accounts) <= len(order); start++ {
			seen := map[string]bool{}
			for _, scope := range order[start : start+len(accounts)] {
				if seen[scope] {
					t.Fatalf("%s repeated a scope within one cycle: %v", lane, order)
				}
				seen[scope] = true
			}
		}
	}
}
