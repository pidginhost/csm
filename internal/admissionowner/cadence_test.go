package admissionowner

import (
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/firewall"
	"github.com/pidginhost/csm/internal/store"
)

// A degraded clock cannot bound a lease: the admission time stays at its
// high-water mark while the wall clock the engine encodes against is
// behind it. Block picks wait, deferred as an unavailable engine, without
// reaching the engine, and run once wall time catches up.
func TestOwnerDefersBlocksWhileTheClockIsDegraded(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	blocks := newFakeBlocks()
	o := f.start(executeOptions(f, blocks))
	mono := heldMono(t, o)
	queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.9")
	if err := o.do(o.turn); err != nil {
		t.Fatal(err)
	}
	id, _ := queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.10")
	f.host.set(func(h *fakeHost) { h.wall = h.wall.Add(-time.Minute) })
	if err := o.do(o.turn); err != nil {
		t.Fatal(err)
	}
	checks, applies := blocks.calls()
	if c := candidate(t, o, id); c.State != admission.StateQueued || c.Reason != admission.ReasonEngineUnavailable || c.Attempts != 0 || len(checks) != 1 || len(applies) != 1 {
		t.Fatalf("degraded clock: %+v checks=%d applies=%d", c, len(checks), len(applies))
	}
	mono.advance(batchEvery)
	f.host.advance(time.Minute + time.Second)
	if err := o.do(o.turn); err != nil {
		t.Fatal(err)
	}
	if c := candidate(t, o, id); c.State != admission.StateVerified || c.Attempts != 1 {
		t.Fatalf("after the clock recovered: %+v", c)
	}
}

// One batch starts a second at most (spec 5.5). A turn sooner than that
// leaves block picks queued exactly as they were.
func TestOwnerStartsOneBatchASecond(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	blocks := newFakeBlocks()
	o := f.start(executeOptions(f, blocks))
	mono := heldMono(t, o)
	queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.10")
	if err := o.do(o.turn); err != nil {
		t.Fatal(err)
	}
	next, _ := queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.11")
	before := candidate(t, o, next)
	mono.advance(time.Second - time.Nanosecond)
	f.host.advance(time.Second - time.Nanosecond)
	if err := o.do(o.turn); err != nil {
		t.Fatal(err)
	}
	checks, applies := blocks.calls()
	if c := candidate(t, o, next); !reflect.DeepEqual(c, before) || len(checks) != 1 || len(applies) != 1 {
		t.Fatalf("a batch started early: %+v checks=%d applies=%d", c, len(checks), len(applies))
	}
	mono.advance(time.Nanosecond)
	f.host.advance(time.Nanosecond)
	if err := o.do(o.turn); err != nil {
		t.Fatal(err)
	}
	if c := candidate(t, o, next); c.State != admission.StateVerified {
		t.Fatalf("after a second: %+v", c)
	}
}

// With an engine, the first ready batch starts as soon as its drain
// queues it (spec 5.5), not on the next schedule tick.
func TestOwnerRunsTheFirstReadyBatchAfterItsDrain(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	blocks := newFakeBlocks()
	o := f.start(executeOptions(f, blocks))
	mono := heldMono(t, o)
	submitTo(t, o, p, "192.0.2.10", f.host.now())
	if err := o.do(func() error { o.drainTick(); return nil }); err != nil {
		t.Fatal(err)
	}
	if _, applies := blocks.calls(); len(applies) != 1 {
		t.Fatalf("the drained block waited for the schedule: applies=%d", len(applies))
	}
	// Work left for the cadence keeps the schedule due; a later drain that
	// queues nothing still leaves it to the schedule timer.
	queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.11")
	mono.advance(batchEvery / 2)
	if err := o.do(o.turn); err != nil {
		t.Fatal(err)
	}
	mono.advance(batchEvery / 2)
	if err := o.do(func() error { o.drainTick(); return nil }); err != nil {
		t.Fatal(err)
	}
	if _, applies := blocks.calls(); len(applies) != 1 {
		t.Fatalf("a drain without new work ran a turn: applies=%d", len(applies))
	}
}

// A drain that queues nothing new runs no turn, and without an engine, as
// production runs until cutover, previews keep the schedule timer.
func TestOwnerDrainRunsNoTurnWithoutNewWorkOrEngine(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	blocks := newFakeBlocks()
	o := f.start(executeOptions(f, blocks))
	queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.10")
	if err := o.do(func() error { o.drainTick(); return nil }); err != nil {
		t.Fatal(err)
	}
	if _, applies := blocks.calls(); len(applies) != 0 {
		t.Fatalf("a drain without arrivals ran a turn: applies=%d", len(applies))
	}

	g := newOwnerFixture(t)
	preview := g.start(previewOptions(g))
	submitTo(t, preview, p, "192.0.2.11", g.host.now())
	if err := preview.do(func() error { preview.drainTick(); return nil }); err != nil {
		t.Fatal(err)
	}
	if n := outcomes(ledgerStatus(t, preview), admission.DispositionObserve); n != 0 || len(queuedCandidates(t, preview)) != 1 {
		t.Fatalf("a drain without an engine previewed: observed=%d queued=%d", n, len(queuedCandidates(t, preview)))
	}
}

// Checks and ledger refusals consume no batch start. Every dispatch does,
// including an error or ambiguous reply, measured after slow reservation.
func TestOwnerCadenceCountsOnlyDispatches(t *testing.T) {
	for _, ending := range []string{"check_refusal", "reserve_skip", "execution_refusal", "execution_readback", "apply_error", "apply_reply", "rejected", "applied"} {
		t.Run(ending, func(t *testing.T) {
			p := withTestRegistry(t)
			f := newOwnerFixture(t)
			blocks := newFakeBlocks()
			switch ending {
			case "check_refusal":
				blocks.refuse["192.0.2.10"] = firewall.BlockRefusedProtected
			case "apply_error":
				blocks.applyErr = errors.New("apply unavailable")
			case "apply_reply":
				blocks.shortResults = true
			case "rejected":
				blocks.reject = 1
			}
			o := f.start(executeOptions(f, blocks))
			mono := heldMono(t, o)
			reserve := reserveLedger
			setOwnerHook(t, o, &reserveLedger, func(l *store.AdmissionLedger, id admission.CandidateID, lane admission.Lane, expires time.Time) (admission.Candidate, admission.AttemptRecord, bool, error) {
				mono.advance(3 * time.Second)
				if ending == "reserve_skip" {
					return admission.Candidate{}, admission.AttemptRecord{}, false, admission.ErrNotReady
				}
				return reserve(l, id, lane, expires)
			})
			execute := executeLedger
			setOwnerHook(t, o, &executeLedger, func(l *store.AdmissionLedger, ids []admission.ActionID) ([]admission.Intent, bool, error) {
				if ending == "execution_refusal" {
					return nil, false, &admission.Error{Reason: admission.ReasonPendingRecovery}
				}
				intents, granted, err := execute(l, ids)
				if ending == "execution_readback" {
					granted = false
				}
				return intents, granted, err
			})
			queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.10")
			err := o.do(o.turn)
			if ending == "execution_readback" {
				if !errors.Is(err, admission.ErrTransitionConflict) {
					t.Fatalf("readback = %v", err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
			wantApplies := 0
			var wantNext time.Time
			switch ending {
			case "apply_error", "apply_reply", "rejected", "applied":
				wantApplies = 1
				wantNext = mono.read().Add(batchEvery)
			}
			_, applies := blocks.calls()
			if err := o.do(func() error {
				if len(applies) != wantApplies || !o.nextBatch.Equal(wantNext) {
					t.Errorf("dispatches=%d want=%d next=%v want=%v", len(applies), wantApplies, o.nextBatch, wantNext)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// An error leaves the last clock state cached. The turn must stop before
// that formerly sound reading can authorize any work.
func TestOwnerFailedClockCannotExecuteWithCachedTime(t *testing.T) {
	for _, fault := range []string{"read", "tick"} {
		t.Run(fault, func(t *testing.T) {
			p := withTestRegistry(t)
			f := newOwnerFixture(t)
			blocks := newFakeBlocks()
			o := f.start(executeOptions(f, blocks))
			heldMono(t, o)
			id, _ := queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.10")
			before := candidate(t, o, id)
			reading, err := f.host.clock()
			if err != nil {
				t.Fatal(err)
			}
			f.host.set(func(h *fakeHost) {
				if fault == "read" {
					h.clockErr = errors.New("clock unavailable")
				} else {
					h.since = -1
				}
			})
			if err := o.do(o.turn); err == nil {
				t.Fatal("turn ignored a failed clock")
			}
			checks, applies := blocks.calls()
			if c := candidate(t, o, id); !reflect.DeepEqual(c, before) || len(checks) != 0 || len(applies) != 0 {
				t.Fatalf("cached clock authorized work: %+v checks=%d applies=%d", c, len(checks), len(applies))
			}
			f.host.set(func(h *fakeHost) { h.clockErr, h.since = nil, reading.SinceBoot })
			if err := o.do(o.turn); err != nil {
				t.Fatal(err)
			}
			if c := candidate(t, o, id); c.State != admission.StateVerified || c.Attempts != 1 {
				t.Fatalf("clock recovery did not serve work: %+v", c)
			}
		})
	}
}

// NextWake can leave scheduleDue set when cadence blocks execution. One
// drain still runs at most one extra turn, even across several groups.
func TestOwnerDrainRunsAtMostOneTurn(t *testing.T) {
	for _, live := range []bool{false, true} {
		name := "preview"
		if live {
			name = "execution"
		}
		t.Run(name, func(t *testing.T) {
			p := withTestRegistry(t)
			f := newOwnerFixture(t)
			blocks := newFakeBlocks()
			opts := previewOptions(f)
			if live {
				opts = executeOptions(f, blocks)
			}
			o := f.start(opts)
			mono := heldMono(t, o)
			setOwnerHook(t, o, &drainGroup, 1)
			schedule := scheduleLedger
			turns := 0
			setOwnerHook(t, o, &scheduleLedger, func(l *store.AdmissionLedger, limits admission.ScheduleLimits) ([]admission.Pick, error) {
				turns++
				return schedule(l, limits)
			})
			for _, addr := range []string{"192.0.2.10", "192.0.2.11", "192.0.2.12", "192.0.2.13"} {
				submitTo(t, o, p, addr, f.host.now())
			}
			if err := o.do(func() error { o.drainTick(); return o.scheduleErr }); err != nil {
				t.Fatal(err)
			}
			if o.ingress.Len() != 0 {
				t.Fatal("fixture did not drain every group")
			}
			if !live {
				if turns != 0 || len(queuedCandidates(t, o)) != 4 || outcomes(ledgerStatus(t, o), admission.DispositionObserve) != 0 {
					t.Fatalf("production drain changed preview scheduling: turns=%d", turns)
				}
				if err := o.do(func() error { o.schedule(); return o.scheduleErr }); err != nil {
					t.Fatal(err)
				}
				if turns != 1 || outcomes(ledgerStatus(t, o), admission.DispositionObserve) != 4 {
					t.Fatalf("schedule did not preview all work once: turns=%d", turns)
				}
				return
			}
			if _, applies := blocks.calls(); turns != 1 || len(applies) != 1 || len(applies[0]) != 4 {
				t.Fatalf("drain turns=%d applies=%v", turns, applies)
			}
			submitTo(t, o, p, "192.0.2.14", f.host.now())
			if err := o.do(func() error {
				o.drainTick()
				if !o.scheduleDue {
					t.Error("cadence-blocked work lost its next schedule")
				}
				o.drainTick()
				return o.scheduleErr
			}); err != nil {
				t.Fatal(err)
			}
			if _, applies := blocks.calls(); turns != 2 || len(applies) != 1 {
				t.Fatalf("cadence-blocked drain repeated: turns=%d applies=%d", turns, len(applies))
			}
			mono.advance(batchEvery)
			f.host.advance(batchEvery)
			if err := o.do(func() error { o.schedule(); return o.scheduleErr }); err != nil {
				t.Fatal(err)
			}
			if _, applies := blocks.calls(); turns != 3 || len(applies) != 2 || len(applies[1]) != 1 {
				t.Fatalf("schedule did not serve waiting work: turns=%d applies=%v", turns, applies)
			}
		})
	}
}
