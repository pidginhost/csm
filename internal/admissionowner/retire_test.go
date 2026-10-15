package admissionowner

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/firewall"
	"github.com/pidginhost/csm/internal/store"
)

// unknownBlock runs one pick to an unknown outcome and delivers its rows.
func unknownBlock(t *testing.T, o *Owner, p *admission.Producer, f *ownerFixture, blocks *fakeBlocks, addr string) (admission.Candidate, admission.AttemptRecord) {
	t.Helper()
	blocks.set(func(b *fakeBlocks) { b.results[addr] = firewall.BlockResult{Effect: firewall.BlockUnknown} })
	id, _ := queuedAt(t, o, p, f.host, admission.SeverityHigh, addr)
	if err := o.do(o.turn); err != nil {
		t.Fatal(err)
	}
	if err := o.do(o.deliverAudit); err != nil {
		t.Fatal(err)
	}
	c := candidate(t, o, id)
	if c.State != admission.StateUnknown {
		t.Fatalf("candidate = %+v, want an unknown outcome", c)
	}
	return c, attemptOf(t, o, c)
}

// An unknown attempt is retired once its expiry has passed and the engine
// finds nothing of it (spec 5.4, design P7): the engine removes its row,
// then the ledger retires it. The turn wakes for that expiry; nothing is
// asked of the engine before it.
func TestOwnerRetiresAnUnknownOnceTheEngineFindsNothing(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	blocks := newFakeBlocks()
	o := f.start(executeOptions(f, blocks))
	mono := heldMono(t, o)
	c, a := unknownBlock(t, o, p, f, blocks, "192.0.2.10")
	if err := o.do(func() error {
		if !o.wakeAt.Equal(mono.read().Add(c.ExpiresAt.Sub(o.now))) {
			t.Errorf("turn wakes at %v; want no later than the unknown's expiry", o.wakeAt)
		}
		o.scheduleDue = false
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := o.do(func() error { o.schedule(); return o.scheduleErr }); err != nil {
		t.Fatal(err)
	}
	if calls := blocks.retireCalls(); len(calls) != 0 {
		t.Fatalf("retirement asked the engine before the expiry: %+v", calls)
	}
	mono.advance(25 * time.Hour)
	f.host.advance(25 * time.Hour)
	if err := o.do(func() error { o.schedule(); return o.scheduleErr }); err != nil {
		t.Fatal(err)
	}
	calls := blocks.retireCalls()
	if len(calls) != 1 || len(calls[0]) != 1 || calls[0][0] != (firewall.BlockAction{Action: string(a.Attempt.ID), IP: "192.0.2.10"}) {
		t.Fatalf("engine retirement calls = %+v", calls)
	}
	if got := attemptOf(t, o, c); !got.Retired || got.State != admission.StateUnknown {
		t.Fatalf("attempt after retirement = %+v", got)
	}
	if st := ledgerStatus(t, o); st.Unresolved.Unknown != 0 {
		t.Fatalf("unresolved after retirement = %+v", st.Unresolved)
	}
}

// Forward-step acceptance (1.5a gate c): a wall step makes the expiry look
// past; the step itself is a degraded reading and retires nothing, and on
// the next clean reading the engine still finds the element, so nothing is
// retired. Once the element is gone a later pass retires it.
func TestOwnerKeepsAnUnknownWhoseElementRemains(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	blocks := newFakeBlocks()
	o := f.start(executeOptions(f, blocks))
	mono := heldMono(t, o)
	c, _ := unknownBlock(t, o, p, f, blocks, "192.0.2.10")
	blocks.set(func(b *fakeBlocks) { b.present["192.0.2.10"] = true })
	f.host.set(func(h *fakeHost) { h.wall = h.wall.Add(25 * time.Hour) })
	if err := o.do(o.turn); err != nil {
		t.Fatal(err)
	}
	if calls := blocks.retireCalls(); len(calls) != 0 {
		t.Fatalf("a degraded reading asked to retire: %+v", calls)
	}
	mono.advance(time.Second)
	f.host.advance(time.Second)
	if err := o.do(o.turn); err != nil {
		t.Fatal(err)
	}
	if calls := blocks.retireCalls(); len(calls) != 1 {
		t.Fatalf("clean reading retirement calls = %+v, want one check", calls)
	}
	if got := attemptOf(t, o, c); got.Retired {
		t.Fatal("an unknown whose element remains was retired")
	}
	blocks.set(func(b *fakeBlocks) { delete(b.present, "192.0.2.10") })
	if err := o.do(o.turn); err != nil {
		t.Fatal(err)
	}
	if calls := blocks.retireCalls(); len(calls) != 1 {
		t.Fatalf("a held unknown was checked again at once: %+v", calls)
	}
	mono.advance(retireRecheck)
	f.host.advance(retireRecheck)
	if err := o.do(o.turn); err != nil {
		t.Fatal(err)
	}
	if got := attemptOf(t, o, c); !got.Retired {
		t.Fatal("the unknown was not retired once its element was gone")
	}
}

// A held attempt waits on its own monotonic retry. Until that retry or a
// noted expiry is due, a turn must not list every unresolved intent again.
func TestOwnerRetirementHeldWaitSkipsScans(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	blocks := newFakeBlocks()
	o := f.start(executeOptions(f, blocks))
	mono := heldMono(t, o)
	unknownBlock(t, o, p, f, blocks, "192.0.2.11")
	blocks.set(func(b *fakeBlocks) { b.present["192.0.2.11"] = true })
	f.host.advance(25 * time.Hour)
	mono.advance(25 * time.Hour)
	if err := o.do(o.turn); err != nil {
		t.Fatal(err)
	}
	if calls := blocks.retireCalls(); len(calls) != 1 {
		t.Fatalf("retirement calls = %d, want one check", len(calls))
	}
	list, scans := unresolvedIntents, 0
	setOwnerHook(t, o, &unresolvedIntents, func(l *store.AdmissionLedger) ([]admission.Intent, error) {
		scans++
		return list(l)
	})
	f.host.advance(time.Second)
	mono.advance(time.Second)
	if err := o.do(o.turn); err != nil {
		t.Fatal(err)
	}
	if scans != 0 {
		t.Fatalf("a turn inside the held wait listed intents %d times", scans)
	}
	f.host.advance(retireRecheck)
	mono.advance(retireRecheck)
	if err := o.do(o.turn); err != nil {
		t.Fatal(err)
	}
	if scans != 1 || len(blocks.retireCalls()) != 2 {
		t.Fatalf("recheck scans = %d, engine calls = %d", scans, len(blocks.retireCalls()))
	}
}

// Kill point: the engine removed the row and the process stopped before
// the ledger retired the attempt. The next start finds it clear again and
// retires it, once.
func TestOwnerRetirementConvergesAfterACrash(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	blocks := newFakeBlocks()
	o := f.start(executeOptions(f, blocks))
	mono := heldMono(t, o)
	c, _ := unknownBlock(t, o, p, f, blocks, "192.0.2.10")
	crash := errors.New("fixture stop before the ledger retires")
	retire, stopped := retireLedger, false
	setOwnerHook(t, o, &retireLedger, func(l *store.AdmissionLedger, id admission.ActionID) (admission.Candidate, admission.AttemptRecord, bool, error) {
		if !stopped {
			if calls := blocks.retireCalls(); len(calls) != 1 || len(calls[0]) != 1 || calls[0][0].Action != string(id) {
				t.Errorf("ledger retirement preceded engine cleanup: %+v", calls)
				return admission.Candidate{}, admission.AttemptRecord{}, false, crash
			}
			before, readErr := l.Attempt(id)
			if readErr != nil || before.Retired || before.State != admission.StateUnknown {
				t.Errorf("crash boundary lost unknown: %+v, %v", before, readErr)
				return admission.Candidate{}, admission.AttemptRecord{}, false, crash
			}
			stopped = true
			return admission.Candidate{}, admission.AttemptRecord{}, false, crash
		}
		return retire(l, id)
	})
	mono.advance(25 * time.Hour)
	f.host.advance(25 * time.Hour)
	if err := o.do(o.turn); !errors.Is(err, crash) {
		t.Fatalf("missing retirement write failure: %v", err)
	}
	o.halt(false)
	o = f.start(executeOptions(f, blocks))
	if err := o.do(o.turn); err != nil {
		t.Fatal(err)
	}
	if got := attemptOf(t, o, c); !got.Retired {
		t.Fatal("retirement did not converge after the crash")
	}
	if calls := blocks.retireCalls(); len(calls) != 2 {
		t.Fatalf("engine retirement calls = %d, want one per pass", len(calls))
	}
}

// An engine that cannot check retires nothing and is asked again only after
// a backoff; the turn itself does not fail.
func TestOwnerRetirementBacksOffOnEngineErrors(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	blocks := newFakeBlocks()
	o := f.start(executeOptions(f, blocks))
	mono := heldMono(t, o)
	turn := func() error { o.scheduleDue = true; o.schedule(); return o.scheduleErr }
	c, _ := unknownBlock(t, o, p, f, blocks, "192.0.2.10")
	blocks.set(func(b *fakeBlocks) { b.retireErr = errors.New("fixture dump failure") })
	mono.advance(25 * time.Hour)
	f.host.advance(25 * time.Hour)
	for i, wait := range []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second, 16 * time.Second, 32 * time.Second, time.Minute, time.Minute} {
		if err := o.do(turn); err != nil {
			t.Fatalf("an engine check failure failed the turn: %v", err)
		}
		if calls := blocks.retireCalls(); len(calls) != i+1 {
			t.Fatalf("retry %d calls = %d", i, len(calls))
		}
		if err := o.do(func() error {
			if !o.wakeAt.Equal(mono.read().Add(wait)) {
				t.Errorf("retry %d wake = %v, want %v", i, o.wakeAt, mono.read().Add(wait))
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		mono.advance(wait - time.Nanosecond)
		f.host.advance(wait - time.Nanosecond)
		if err := o.do(turn); err != nil {
			t.Fatal(err)
		}
		if len(blocks.retireCalls()) != i+1 || attemptOf(t, o, c).Retired {
			t.Fatal("engine failure retried early or retired the unknown")
		}
		mono.advance(time.Nanosecond)
		f.host.advance(time.Nanosecond)
	}
	blocks.set(func(b *fakeBlocks) { b.retireErr = nil })
	if err := o.do(turn); err != nil {
		t.Fatal(err)
	}
	if got := attemptOf(t, o, c); !got.Retired {
		t.Fatal("retirement did not resume after the backoff")
	}
	if err := o.do(func() error {
		if o.retireWait != 0 || !o.retireAt.IsZero() {
			t.Error("successful retirement kept the engine backoff")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// A pass sends the engine only the unknowns whose expiry has passed; a
// later one waits for its own.
func TestOwnerRetiresOnlyExpiredUnknowns(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	blocks := newFakeBlocks()
	o := f.start(executeOptions(f, blocks))
	mono := heldMono(t, o)
	first, a := unknownBlock(t, o, p, f, blocks, "192.0.2.10")
	mono.advance(12 * time.Hour)
	f.host.advance(12 * time.Hour)
	if err := o.do(o.tick); err != nil {
		t.Fatal(err)
	}
	second, _ := unknownBlock(t, o, p, f, blocks, "192.0.2.11")
	mono.advance(12*time.Hour + time.Second)
	f.host.advance(12*time.Hour + time.Second)
	if err := o.do(o.turn); err != nil {
		t.Fatal(err)
	}
	calls := blocks.retireCalls()
	if len(calls) != 1 || len(calls[0]) != 1 || calls[0][0].Action != string(a.Attempt.ID) {
		t.Fatalf("engine retirement calls = %+v; want only the expired unknown", calls)
	}
	if !attemptOf(t, o, first).Retired || attemptOf(t, o, second).Retired {
		t.Fatal("retirement did not follow each unknown's own expiry")
	}
}

// Seed an executing or unknown attempt without calling the engine. This
// also exercises recovery discovery without a finishPending notification.
func retirementAttempt(t *testing.T, o *Owner, p *admission.Producer, f *ownerFixture, addr string, unknown bool) admission.AttemptRecord {
	t.Helper()
	id, _ := queuedAt(t, o, p, f.host, admission.SeverityHigh, addr)
	var a admission.AttemptRecord
	if err := o.do(func() error {
		var reserveErr error
		_, a, _, reserveErr = o.ledger.Reserve(id, admission.LaneGeneral, o.now.Add(time.Hour))
		if reserveErr != nil {
			return reserveErr
		}
		if _, _, _, reserveErr = o.ledger.Execute(a.Attempt.ID); reserveErr != nil {
			return reserveErr
		}
		if unknown {
			_, a, reserveErr = o.ledger.Finish(a.Attempt.ID, admission.DispositionUnknown)
		}
		return reserveErr
	}); err != nil {
		t.Fatal(err)
	}
	return a
}

// A held prefix larger than one batch cannot starve later clear intents.
// A pass stays bounded and each held action observes its own retry wait.
func TestOwnerRetirementPassesAHeldBatch(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	blocks := newFakeBlocks()
	o := f.start(executeOptions(f, blocks))
	mono := heldMono(t, o)
	for i := 1; i <= firewall.MaxBlockBatchMembers+1; i++ {
		retirementAttempt(t, o, p, f, fmt.Sprintf("192.0.2.%d", i), true)
		f.host.advance(10 * time.Second)
		mono.advance(10 * time.Second)
		if err := o.do(o.tick); err != nil {
			t.Fatal(err)
		}
	}
	if err := o.do(o.deliverAudit); err != nil {
		t.Fatal(err)
	}
	var intents []admission.Intent
	if err := o.do(func() error {
		var readErr error
		intents, readErr = o.ledger.UnresolvedIntents()
		return readErr
	}); err != nil {
		t.Fatal(err)
	}
	if len(intents) != firewall.MaxBlockBatchMembers+1 {
		t.Fatalf("fixture has %d intents", len(intents))
	}
	blocks.set(func(b *fakeBlocks) {
		for _, in := range intents[:firewall.MaxBlockBatchMembers] {
			addr, _ := in.Target.Addr()
			b.present[addr.String()] = true
		}
	})
	f.host.advance(2 * time.Hour)
	mono.advance(2 * time.Hour)
	for range 2 {
		if err := o.do(o.turn); err != nil {
			t.Fatal(err)
		}
	}
	calls := blocks.retireCalls()
	last := intents[len(intents)-1].Action
	if len(calls) != 2 || len(calls[0]) != firewall.MaxBlockBatchMembers || len(calls[1]) != 1 || calls[1][0].Action != string(last) {
		t.Fatalf("held prefix monopolized retirement: %+v", calls)
	}
	if st := ledgerStatus(t, o); st.Unresolved.Unknown != firewall.MaxBlockBatchMembers {
		t.Fatalf("later intent stayed unresolved: %+v", st.Unresolved)
	}
	if err := o.do(o.turn); err != nil {
		t.Fatal(err)
	}
	if len(blocks.retireCalls()) != 2 {
		t.Fatal("held entries were checked again inside their minute")
	}
	blocks.set(func(b *fakeBlocks) { clear(b.present) })
	f.host.advance(retireRecheck)
	mono.advance(retireRecheck)
	if err := o.do(o.turn); err != nil {
		t.Fatal(err)
	}
	if st := ledgerStatus(t, o); st.Unresolved.Unknown != 0 {
		t.Fatalf("held batch did not recover: %+v", st.Unresolved)
	}
}

// Running attempts have no terminal outcome to retire. In particular a
// failed Finish must never let retirement remove their rows.
func TestOwnerRetirementIgnoresRunningAttempts(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	blocks := newFakeBlocks()
	o := f.start(executeOptions(f, blocks))
	mono := heldMono(t, o)
	a := retirementAttempt(t, o, p, f, "192.0.2.80", false)
	f.host.advance(2 * time.Hour)
	mono.advance(2 * time.Hour)
	if err := o.do(o.turn); err != nil {
		t.Fatal(err)
	}
	if len(blocks.retireCalls()) != 0 {
		t.Fatal("an executing attempt reached engine retirement")
	}
	if err := o.do(func() error {
		got, readErr := o.ledger.Attempt(a.Attempt.ID)
		if readErr != nil || got.State != admission.StateExecuting || got.Retired {
			t.Errorf("running attempt changed: %+v, %v", got, readErr)
		}
		return readErr
	}); err != nil {
		t.Fatal(err)
	}
}

// An undelivered outcome or a separately degraded ledger clock keeps its
// intent, has a future wake, and retires after the dependency recovers.
func TestOwnerRetirementWaitsForLedgerReadiness(t *testing.T) {
	for _, degraded := range []bool{false, true} {
		p := withTestRegistry(t)
		f := newOwnerFixture(t)
		blocks := newFakeBlocks()
		o := f.start(executeOptions(f, blocks))
		mono := heldMono(t, o)
		a := retirementAttempt(t, o, p, f, "192.0.2.81", true)
		if degraded {
			if err := o.do(o.deliverAudit); err != nil {
				t.Fatal(err)
			}
		}
		f.host.advance(2 * time.Hour)
		mono.advance(2 * time.Hour)
		if err := o.do(func() error {
			if tickErr := o.tick(); tickErr != nil {
				return tickErr
			}
			if degraded {
				reading, readErr := f.host.clock()
				if readErr != nil {
					return readErr
				}
				reading.Wall = reading.Wall.Add(-time.Hour)
				if tick, tickErr := o.ledger.Tick(reading); tickErr != nil || !tick.Degraded {
					return fmt.Errorf("ledger not degraded: %+v, %v", tick, tickErr)
				}
			}
			if retireErr := o.retire(); retireErr != nil {
				return retireErr
			}
			got, readErr := o.ledger.Attempt(a.Attempt.ID)
			if readErr != nil || got.Retired || !o.retireRetry[a.Attempt.ID].After(mono.read()) {
				t.Errorf("unready retirement = %+v, %v; retry %v, now %v", got, readErr, o.retireRetry[a.Attempt.ID], mono.read())
			}
			return readErr
		}); err != nil {
			t.Fatal(err)
		}
		if err := o.do(o.retire); err != nil {
			t.Fatal(err)
		}
		if len(blocks.retireCalls()) != 1 {
			t.Fatal("unready ledger caused an immediate engine retry")
		}
		if err := o.do(o.deliverAudit); err != nil {
			t.Fatal(err)
		}
		f.host.advance(time.Second)
		mono.advance(time.Second)
		if degraded {
			// The correction is itself one degraded reading.
			if err := o.do(o.tick); err != nil {
				t.Fatal(err)
			}
		}
		if err := o.do(o.turn); err != nil {
			t.Fatal(err)
		}
		if st := ledgerStatus(t, o); st.Unresolved.Unknown != 0 {
			t.Fatalf("readiness recovery lost retirement: %+v", st.Unresolved)
		}
		o.Stop()
	}
}

// A malformed engine answer has the same backoff as a failed snapshot;
// no subset may retire from a truncated response.
func TestOwnerRetirementRejectsShortAnswer(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	blocks := newFakeBlocks()
	o := f.start(executeOptions(f, blocks))
	mono := heldMono(t, o)
	c, _ := unknownBlock(t, o, p, f, blocks, "192.0.2.83")
	blocks.set(func(b *fakeBlocks) { b.retireShort = true })
	f.host.advance(25 * time.Hour)
	mono.advance(25 * time.Hour)
	for range 2 {
		if err := o.do(o.turn); err != nil {
			t.Fatal(err)
		}
	}
	if attemptOf(t, o, c).Retired || len(blocks.retireCalls()) != 1 {
		t.Fatal("short answer retired work or bypassed backoff")
	}
	blocks.set(func(b *fakeBlocks) { b.retireShort = false })
	f.host.advance(time.Second)
	mono.advance(time.Second)
	if err := o.do(o.turn); err != nil {
		t.Fatal(err)
	}
	if !attemptOf(t, o, c).Retired {
		t.Fatal("retirement did not resume after a complete answer")
	}
}

// Degraded time and temporary engine absence both retain a future wake,
// even when no queued work or new arrival can drive another turn.
func TestOwnerRetirementWakesAfterUnavailablePrerequisites(t *testing.T) {
	for _, mode := range []string{"engine", "clock"} {
		t.Run(mode, func(t *testing.T) {
			p := withTestRegistry(t)
			f := newOwnerFixture(t)
			blocks := newFakeBlocks()
			opts := executeOptions(f, blocks)
			available := true
			opts.Blocks = func() BlockEngine {
				if !available {
					return nil
				}
				return blocks
			}
			o := f.start(opts)
			mono := heldMono(t, o)
			c, _ := unknownBlock(t, o, p, f, blocks, "192.0.2.84")
			f.host.advance(25 * time.Hour)
			mono.advance(25 * time.Hour)
			if mode == "clock" {
				f.host.set(func(h *fakeHost) { h.wall = h.wall.Add(time.Hour) })
			}
			if err := o.do(func() error {
				available = mode != "engine"
				o.schedule()
				if !o.wakeAt.Equal(mono.read().Add(time.Second)) {
					t.Errorf("unavailable %s wake = %v", mode, o.wakeAt)
				}
				return o.scheduleErr
			}); err != nil {
				t.Fatal(err)
			}
			if len(blocks.retireCalls()) != 0 || attemptOf(t, o, c).Retired {
				t.Fatal("unavailable prerequisite reached retirement")
			}
			f.host.advance(time.Second)
			mono.advance(time.Second)
			if err := o.do(func() error {
				available = true
				o.schedule()
				return o.scheduleErr
			}); err != nil {
				t.Fatal(err)
			}
			if !attemptOf(t, o, c).Retired || len(blocks.retireCalls()) != 1 {
				t.Fatal("recovered prerequisite did not wake retirement")
			}
		})
	}
}

// Retry waits use elapsed time even when a trusted admission reading has
// not advanced. Recovery must be driven by schedule's wake, not a new arrival.
func TestOwnerRetirementRetryUsesElapsedTime(t *testing.T) {
	for _, pass := range []bool{false, true} {
		t.Run(fmt.Sprintf("pass=%t", pass), func(t *testing.T) {
			p := withTestRegistry(t)
			f := newOwnerFixture(t)
			blocks := newFakeBlocks()
			o := f.start(executeOptions(f, blocks))
			mono := heldMono(t, o)
			c, _ := unknownBlock(t, o, p, f, blocks, "192.0.2.85")
			retire, calls := retireLedger, 0
			setOwnerHook(t, o, &retireLedger, func(l *store.AdmissionLedger, id admission.ActionID) (admission.Candidate, admission.AttemptRecord, bool, error) {
				calls++
				if calls == 1 {
					return admission.Candidate{}, admission.AttemptRecord{}, false, admission.ErrNotReady
				}
				return retire(l, id)
			})
			f.host.advance(25 * time.Hour)
			mono.advance(25 * time.Hour)
			if err := o.do(func() error { o.scheduleDue = true; o.schedule(); return o.scheduleErr }); err != nil {
				t.Fatal(err)
			}
			// An unrelated early turn recomputes the wake while this action
			// waits; with another noted expiry due, it also runs a pass.
			f.host.advance(500 * time.Millisecond)
			mono.advance(500 * time.Millisecond)
			if err := o.do(func() error {
				o.scheduleDue = true
				if pass {
					o.noteRetirement(o.now)
				}
				o.schedule()
				return o.scheduleErr
			}); err != nil {
				t.Fatal(err)
			}
			if len(blocks.retireCalls()) != 1 {
				t.Fatal("early turn bypassed the per-action wait")
			}
			// A sub-second discrepancy is within the admission clock's tolerance.
			// The wall stays still while the rest of the monotonic wait passes.
			f.host.set(func(h *fakeHost) { h.since += 500 * time.Millisecond })
			mono.advance(500 * time.Millisecond)
			if err := o.do(func() error { o.schedule(); return o.scheduleErr }); err != nil {
				t.Fatal(err)
			}
			if !attemptOf(t, o, c).Retired || len(blocks.retireCalls()) != 2 {
				t.Fatal("elapsed retry lost its only wake while admission time stood still")
			}
			if err := o.do(func() error {
				if len(o.retireRetry) != 0 || !o.wakeAt.IsZero() || o.scheduleDue {
					t.Errorf("settled retirement retained work: retry %v, wake %v, due %t", o.retireRetry, o.wakeAt, o.scheduleDue)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// A prolonged rollback cannot turn a one-second degraded retry into a
// wake that disappears or moves farther into the future on each turn.
func TestOwnerRetirementKeepsDegradedWakes(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	blocks := newFakeBlocks()
	o := f.start(executeOptions(f, blocks))
	mono := heldMono(t, o)
	c, _ := unknownBlock(t, o, p, f, blocks, "192.0.2.86")
	f.host.advance(25 * time.Hour)
	mono.advance(25 * time.Hour)
	if err := o.do(o.tick); err != nil {
		t.Fatal(err)
	}
	f.host.set(func(h *fakeHost) { h.wall = h.wall.Add(-time.Hour) })
	if err := o.do(func() error { o.scheduleDue = true; return nil }); err != nil {
		t.Fatal(err)
	}
	for range 3 {
		if err := o.do(func() error {
			o.schedule()
			if !o.wakeAt.Equal(mono.read().Add(time.Second)) {
				t.Errorf("degraded retry wake = %v, now %v", o.wakeAt, mono.read())
			}
			return o.scheduleErr
		}); err != nil {
			t.Fatal(err)
		}
		f.host.advance(time.Second)
		mono.advance(time.Second)
	}
	if len(blocks.retireCalls()) != 0 || attemptOf(t, o, c).Retired {
		t.Fatal("degraded clock permitted retirement")
	}
	f.host.set(func(h *fakeHost) { h.wall = h.wall.Add(time.Hour) })
	for range 2 {
		if err := o.do(func() error { o.schedule(); return o.scheduleErr }); err != nil {
			t.Fatal(err)
		}
		f.host.advance(time.Second)
		mono.advance(time.Second)
	}
	if !attemptOf(t, o, c).Retired {
		t.Fatal("clock recovery lost retirement without a new arrival")
	}
}

// Time spent retiring another action must not be added to a held action's
// wait. Once that wait passes during the call, the next turn is due now.
func TestOwnerRetirementWakeSurvivesSlowCheck(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	blocks := newFakeBlocks()
	o := f.start(executeOptions(f, blocks))
	mono := heldMono(t, o)
	first := retirementAttempt(t, o, p, f, "192.0.2.87", true)
	f.host.advance(30 * time.Second)
	mono.advance(30 * time.Second)
	if err := o.do(o.tick); err != nil {
		t.Fatal(err)
	}
	second := retirementAttempt(t, o, p, f, "192.0.2.88", true)
	if err := o.do(o.deliverAudit); err != nil {
		t.Fatal(err)
	}
	blocks.set(func(b *fakeBlocks) { b.present["192.0.2.87"] = true })
	f.host.advance(time.Hour - 29*time.Second)
	mono.advance(time.Hour - 29*time.Second)
	if err := o.do(func() error { o.scheduleDue = true; o.schedule(); return o.scheduleErr }); err != nil {
		t.Fatal(err)
	}
	blocks.set(func(b *fakeBlocks) {
		b.retireStep = func(actions []firewall.BlockAction) {
			if actions[0].Action == string(second.Attempt.ID) {
				f.host.advance(35 * time.Second)
				mono.advance(35 * time.Second)
			}
		}
	})
	f.host.advance(29 * time.Second)
	mono.advance(29 * time.Second)
	if err := o.do(func() error {
		o.schedule()
		if o.wakeAt.IsZero() || o.wakeAt.After(mono.read()) {
			t.Errorf("slow call extended an elapsed wait: wake %v, now %v", o.wakeAt, mono.read())
		}
		return o.scheduleErr
	}); err != nil {
		t.Fatal(err)
	}
	blocks.set(func(b *fakeBlocks) { clear(b.present) })
	if err := o.do(func() error {
		o.schedule()
		got, err := o.ledger.Attempt(first.Attempt.ID)
		if err != nil || !got.Retired || len(o.retireRetry) != 0 || !o.wakeAt.IsZero() {
			t.Errorf("slow-check recovery = %+v, %v; retries %v, wake %v", got, err, o.retireRetry, o.wakeAt)
		}
		return o.scheduleErr
	}); err != nil {
		t.Fatal(err)
	}
}

// A full retirement batch followed only by executing intents has no more
// retirable work. It must neither poll their future expiry nor spin now.
func TestOwnerRetirementDoesNotWakeForRunningTail(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	blocks := newFakeBlocks()
	o := f.start(executeOptions(f, blocks))
	mono := heldMono(t, o)
	for i := 1; i <= firewall.MaxBlockBatchMembers+1; i++ {
		retirementAttempt(t, o, p, f, fmt.Sprintf("198.51.100.%d", i), false)
		f.host.advance(10 * time.Second)
		mono.advance(10 * time.Second)
		if err := o.do(o.tick); err != nil {
			t.Fatal(err)
		}
	}
	if err := o.do(func() error {
		o.scheduleDue = true
		o.schedule()
		if !o.wakeAt.IsZero() {
			t.Errorf("running attempts created an expiry wake: %v", o.wakeAt)
		}
		intents, err := o.ledger.UnresolvedIntents()
		if err != nil {
			return err
		}
		if len(intents) != firewall.MaxBlockBatchMembers+1 {
			return fmt.Errorf("fixture has %d intents", len(intents))
		}
		for _, in := range intents[:firewall.MaxBlockBatchMembers] {
			if _, _, err = o.ledger.Finish(in.Action, admission.DispositionUnknown); err != nil {
				return err
			}
		}
		return o.deliverAudit()
	}); err != nil {
		t.Fatal(err)
	}
	f.host.advance(2 * time.Hour)
	mono.advance(2 * time.Hour)
	if err := o.do(func() error {
		o.scheduleDue = true
		o.schedule()
		if !o.wakeAt.IsZero() || o.scheduleDue {
			t.Errorf("running tail left a busy wake: %v, due %t", o.wakeAt, o.scheduleDue)
		}
		return o.scheduleErr
	}); err != nil {
		t.Fatal(err)
	}
	if calls := blocks.retireCalls(); len(calls) != 1 || len(calls[0]) != firewall.MaxBlockBatchMembers {
		t.Fatalf("running tail reached retirement: %+v", calls)
	}
}

// An unexpired unknown can expire while a different action's check runs.
// Its wake is anchored to the clock reading at turn entry, not call return.
func TestOwnerRetirementExpirySurvivesSlowCheck(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	blocks := newFakeBlocks()
	o := f.start(executeOptions(f, blocks))
	mono := heldMono(t, o)
	first := retirementAttempt(t, o, p, f, "192.0.2.89", true)
	f.host.advance(30 * time.Second)
	mono.advance(30 * time.Second)
	if err := o.do(o.tick); err != nil {
		t.Fatal(err)
	}
	second := retirementAttempt(t, o, p, f, "192.0.2.90", true)
	if err := o.do(o.deliverAudit); err != nil {
		t.Fatal(err)
	}
	blocks.set(func(b *fakeBlocks) {
		b.retireStep = func(actions []firewall.BlockAction) {
			if actions[0].Action == string(first.Attempt.ID) {
				f.host.advance(35 * time.Second)
				mono.advance(35 * time.Second)
			}
		}
	})
	f.host.advance(time.Hour - 29*time.Second)
	mono.advance(time.Hour - 29*time.Second)
	if err := o.do(func() error {
		o.scheduleDue = true
		o.schedule()
		if o.wakeAt.IsZero() || o.wakeAt.After(mono.read()) {
			t.Errorf("slow call moved an expiry wake: %v, now %v", o.wakeAt, mono.read())
		}
		return o.scheduleErr
	}); err != nil {
		t.Fatal(err)
	}
	if err := o.do(func() error {
		o.schedule()
		got, err := o.ledger.Attempt(second.Attempt.ID)
		if err != nil || !got.Retired || !o.wakeAt.IsZero() {
			t.Errorf("expired during call: %+v, %v; wake %v", got, err, o.wakeAt)
		}
		return o.scheduleErr
	}); err != nil {
		t.Fatal(err)
	}
}
