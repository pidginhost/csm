package admissionowner

import (
	"errors"
	"testing"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/store"
)

// A reader can observe the status published by runTurn before schedule
// returns. Settlement must not expose the error from an earlier turn.
func TestOwnerSettlementPublishesRecoveredTurn(t *testing.T) {
	withTestRegistry(t)
	f := newOwnerFixture(t)
	o := f.start(previewOptions(f))
	schedule := scheduleLedger
	failure := errors.New("fixture schedule failure")
	setOwnerHook(t, o, &scheduleLedger, func(*store.AdmissionLedger, admission.ScheduleLimits, map[admission.CandidateID]admission.Answer) ([]admission.Pick, error) {
		return nil, failure
	})
	if err := o.do(func() error { o.schedule(); return nil }); err != nil {
		t.Fatal(err)
	}
	if s := o.Status().Owner; s.Settled || s.TurnError != "scheduling the queue: "+failure.Error() {
		t.Fatalf("failed first turn: %+v", s)
	}
	setOwnerHook(t, o, &scheduleLedger, schedule)
	// Stop at runTurn's return, before schedule can publish another status.
	turn(t, o)
	if s := o.Status().Owner; !s.Settled || s.TurnError != "" {
		t.Fatalf("recovered first turn: %+v", s)
	}
}

// Doctor rates an executing owner's outages as warnings until the owner
// has completed a turn in this process, so the status says when that
// happened. A turn that fails does not count.
func TestOwnerSettlesAfterItsFirstGoodTurn(t *testing.T) {
	withTestRegistry(t)
	f := newOwnerFixture(t)
	o := f.start(executeOptions(f, newFakeBlocks()))
	if o.status().Owner.Settled {
		t.Fatal("settled before any turn")
	}
	schedule := scheduleLedger
	setOwnerHook(t, o, &scheduleLedger, func(*store.AdmissionLedger, admission.ScheduleLimits, map[admission.CandidateID]admission.Answer) ([]admission.Pick, error) {
		return nil, errors.New("fixture schedule failure")
	})
	if err := o.do(o.turn); err == nil {
		t.Fatal("the turn did not fail")
	}
	if o.status().Owner.Settled {
		t.Fatal("settled by a failed turn")
	}
	setOwnerHook(t, o, &scheduleLedger, schedule)
	turn(t, o)
	// The turn itself publishes the change: doctor reads the last status.
	if !o.Status().Owner.Settled {
		t.Fatal("not settled after a good turn")
	}
}

// Any first turn that completes settles the owner, whatever it does: a
// preview-only turn, a dry-run forecast, a live turn, and a turn that
// only maintains the ledger without selecting work.
func TestOwnerSettlesOnAnyCompletedTurn(t *testing.T) {
	for name, run := range map[string]func(t *testing.T, f *ownerFixture) *Owner{
		"preview": func(t *testing.T, f *ownerFixture) *Owner {
			o := f.start(previewOptions(f))
			turn(t, o)
			return o
		},
		"dry run": func(t *testing.T, f *ownerFixture) *Owner {
			o, _, _ := policyOwner(t, f, newFakeBlocks(), dryPolicy(1))
			turn(t, o)
			return o
		},
		"live": func(t *testing.T, f *ownerFixture) *Owner {
			o, _, _ := policyOwner(t, f, newFakeBlocks(), validPolicy(1))
			turn(t, o)
			return o
		},
		"not selecting": func(t *testing.T, f *ownerFixture) *Owner {
			o, _, _ := policyOwner(t, f, newFakeBlocks(), validPolicy(1))
			if err := o.do(func() error { return o.runTurn(false) }); err != nil {
				t.Fatal(err)
			}
			return o
		},
	} {
		t.Run(name, func(t *testing.T) {
			withTestRegistry(t)
			f := newOwnerFixture(t)
			if o := run(t, f); !o.Status().Owner.Settled {
				t.Fatal("a completed first turn did not settle the owner")
			}
		})
	}
}

// A turn that fails anywhere before its end settles nothing: at the clock
// reading, at the selection, or at the queue snapshot it publishes last.
// Once settled the owner stays settled through a later failed turn and a
// policy reload, and a new process starts unsettled again.
func TestOwnerSettlementSurvivesOnlyItsProcess(t *testing.T) {
	failures := map[string]func(t *testing.T, o *Owner, f *ownerFixture) func(){
		"clock": func(t *testing.T, o *Owner, f *ownerFixture) func() {
			f.host.set(func(h *fakeHost) { h.clockErr = errors.New("fixture clock failure") })
			return func() { f.host.set(func(h *fakeHost) { h.clockErr = nil }) }
		},
		"selection": func(t *testing.T, o *Owner, f *ownerFixture) func() {
			schedule := scheduleLedger
			setOwnerHook(t, o, &scheduleLedger, func(*store.AdmissionLedger, admission.ScheduleLimits, map[admission.CandidateID]admission.Answer) ([]admission.Pick, error) {
				return nil, errors.New("fixture schedule failure")
			})
			return func() { setOwnerHook(t, o, &scheduleLedger, schedule) }
		},
		"snapshot": func(t *testing.T, o *Owner, f *ownerFixture) func() {
			read := readSnapshot
			setOwnerHook(t, o, &readSnapshot, func(*store.AdmissionLedger) (*admission.QueueSnapshot, error) {
				return nil, errors.New("fixture snapshot failure")
			})
			return func() { setOwnerHook(t, o, &readSnapshot, read) }
		},
	}
	for name, fail := range failures {
		t.Run(name, func(t *testing.T) {
			withTestRegistry(t)
			f := newOwnerFixture(t)
			o, r, _ := policyOwner(t, f, newFakeBlocks(), validPolicy(1))
			restore := fail(t, o, f)
			if err := o.do(o.turn); err == nil {
				t.Fatal("the turn did not fail")
			}
			if o.status().Owner.Settled {
				t.Fatal("settled by a turn that failed")
			}
			restore()
			turn(t, o)
			if !o.Status().Owner.Settled {
				t.Fatal("not settled after a good turn")
			}
			restore = fail(t, o, f)
			if err := o.do(o.turn); err == nil {
				t.Fatal("the later turn did not fail")
			}
			restore()
			r.publish(dryPolicy(2))
			if err := o.Reload(); err != nil {
				t.Fatal(err)
			}
			if !o.status().Owner.Settled {
				t.Fatal("a later failure or a reload unsettled the owner")
			}
			o.Stop()
			o, _, _ = policyOwner(t, f, newFakeBlocks(), validPolicy(3))
			if o.status().Owner.Settled {
				t.Fatal("a new process started settled")
			}
		})
	}
}
