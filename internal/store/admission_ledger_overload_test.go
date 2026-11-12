package store

import (
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
)

// reopen replaces the fixture's ledger with a fresh handle on its database
// and records a reading at the fixture's wall time, as a restart does.
func (f *ledgerFixture) reopen() {
	f.t.Helper()
	l, err := OpenAdmissionLedger(f.db, f.reg)
	if err != nil {
		f.t.Fatal(err)
	}
	f.l = l
	f.tickAt(f.wall)
}

// After an overload that deferred every scope's work and a restart, each
// refilled unit serves the next scope, continuing the unfinished rotation:
// every surviving scope is served once before any is served twice.
func TestAdmissionLedgerRecoveryAfterOverloadServesEveryScope(t *testing.T) {
	f := newLedgerFixture(t)
	if err := f.l.SetCeiling(100); err != nil {
		t.Fatal(err)
	}
	var accounts []string
	for i := 0; i < 10; i++ {
		accounts = append(accounts, fmt.Sprintf("acct%02d", i))
	}
	f.refresh(accounts, nil)
	var ids []admission.CandidateID
	for _, a := range accounts {
		ids = append(ids, f.fill(5, evidenceSpec{owner: f.owner(a)})...)
	}
	f.leaveCeilingCredit(1, 0)
	var order []string
	// Spend part of a rotation before the outage so losing its cursor
	// cannot look like a valid fresh start after recovery.
	const beforeOverload = 3
	for step := 0; step < beforeOverload+len(accounts); step++ {
		if step == beforeOverload {
			if picks := f.schedule(fullSchedule); len(picks) != 0 {
				t.Fatalf("an empty ceiling served %+v", picks)
			}
			for _, id := range ids {
				if c := f.candidateOf(id); c.State == admission.StateQueued && c.Reason != admission.ReasonCeiling {
					t.Fatalf("queued work was not deferred for overload: %+v", c)
				}
			}
			f.reopen()
		}
		if step > 0 {
			// The general lane earns one unit at this limit. Recovery
			// must use elapsed refill, not a test-written credit balance.
			f.tickAt(f.wall.Add(45 * time.Second))
		}
		picks := f.schedule(oneEach)
		if len(picks) != 1 || picks[0].Lane != admission.LaneGeneral || picks[0].Cost != 1 {
			t.Fatalf("step %d: picks = %+v", step, picks)
		}
		order = append(order, f.scopeOf(picks[0].ID))
		if _, _, granted, err := f.l.Reserve(picks[0].ID, picks[0].Lane, f.wall.Add(time.Hour)); err != nil || !granted {
			t.Fatalf("step %d: reservation granted = %v, error = %v", step, granted, err)
		}
		if c := f.ceilingState(); c.General.Used != uint32(step+1) || c.Reserved.Used != 0 || c.General.Units() != 0 {
			t.Fatalf("step %d: service charges = %+v", step, c)
		}
	}
	for start := 0; start+len(accounts) <= len(order); start++ {
		seen := map[string]bool{}
		for _, scope := range order[start : start+len(accounts)] {
			if seen[scope] {
				t.Fatalf("scope %s served twice in one rotation across overload: %v", scope, order)
			}
			seen[scope] = true
		}
	}
}

// A lowered ceiling keeps the charges already in its window, across a
// restart: general usage above the whole new ceiling stops both lanes until
// those charges age out (decreased limits).
func TestAdmissionLedgerLoweredCeilingKeepsRetainedCharges(t *testing.T) {
	f := newLedgerFixture(t)
	if err := f.l.SetCeiling(10); err != nil {
		t.Fatal(err)
	}
	ids := f.fill(9, evidenceSpec{})
	for _, id := range ids[:8] {
		f.leaveCeilingCredit(1, 0)
		if _, _, _, err := f.l.Reserve(id, admission.LaneGeneral, f.wall.Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
	}
	direct := f.published(evidenceSpec{producer: f.mail, check: "mail_takeover", target: "192.0.2.11", cursor: "direct", severity: admission.SeverityCritical})
	_, directID := f.enqueue(f.request("192.0.2.11", direct))
	if err := f.l.SetCeiling(5); err != nil {
		t.Fatal(err)
	}
	f.tickAt(f.wall.Add(time.Minute))
	f.reopen()
	if err := f.l.SetCeiling(5); err != nil {
		t.Fatal(err)
	}
	f.leaveCeilingCredit(1, 1)
	before := f.snapshot()
	_, _, _, err := f.l.Reserve(ids[8], admission.LaneGeneral, f.wall.Add(time.Hour))
	wantLedgerReason(t, "general work over the lowered ceiling", err, admission.ReasonCeiling)
	_, _, _, err = f.l.Reserve(directID, admission.LaneDirect, f.wall.Add(time.Hour))
	wantLedgerReason(t, "direct work while general usage exceeds the whole ceiling", err, admission.ReasonCeiling)
	if s := f.ceilingState(); s.General.Used != 8 || s.Reserved.Used != 0 {
		t.Fatalf("retained charges = %+v", s)
	}
	if !reflect.DeepEqual(before, f.snapshot()) {
		t.Fatal("a refused reservation changed the ledger")
	}
	f.tickAt(f.wall.Add(time.Hour))
	f.leaveCeilingCredit(1, 1)
	if _, _, _, err = f.l.Reserve(directID, admission.LaneDirect, f.wall.Add(time.Hour)); err != nil {
		t.Fatalf("after the charges aged out: %v", err)
	}
}
