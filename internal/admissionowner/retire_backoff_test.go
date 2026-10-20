package admissionowner

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/store"
)

// An intent without its attempt is ledger damage. It must neither stop
// unrelated retirements nor bypass the per-action damage recheck.
func TestOwnerRetirementIsolatesMissingAttempt(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	blocks := newFakeBlocks()
	o := f.start(executeOptions(f, blocks))
	mono := heldMono(t, o)
	c, a := unknownBlock(t, o, p, f, blocks, "192.0.2.104")
	missing := admission.ActionID("act_" + strings.Repeat("0", 32))
	list := unresolvedIntents
	keep := true
	setOwnerHook(t, o, &unresolvedIntents, func(l *store.AdmissionLedger) ([]admission.Intent, error) {
		intents, err := list(l)
		if keep && err == nil {
			intents = append([]admission.Intent{{Action: missing, Kind: c.Key.Kind, Target: c.Key.Target, ExpiresAt: a.ExpiresAt}}, intents...)
		}
		return intents, err
	})
	f.host.advance(25 * time.Hour)
	mono.advance(25 * time.Hour)
	if err := o.do(func() error {
		if err := o.tick(); err != nil {
			return err
		}
		err := o.retire()
		if !errors.Is(err, admission.ErrCorruptRecord) || !strings.Contains(err.Error(), string(missing)) {
			t.Errorf("missing attempt did not report damage: %v", err)
		}
		if !o.retireFaults[missing] || !o.retireRetry[missing].Equal(mono.read().Add(retireRecheck)) {
			t.Errorf("missing attempt kept no damage recheck: %v, %v", o.retireFaults, o.retireRetry)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if !attemptOf(t, o, c).Retired {
		t.Error("damaged attempt prevented a healthy retirement")
	}
	for _, advance := range []time.Duration{time.Second, retireRecheck} {
		f.host.advance(advance)
		mono.advance(advance)
		if err := o.do(func() error {
			if err := o.tick(); err != nil {
				return err
			}
			// Another expiry can require a scan before the damaged action
			// is due; the scan must still respect its own wait.
			o.noteRetirement(o.now)
			return o.retire()
		}); err != nil {
			t.Errorf("damage was reported again: %v", err)
		}
	}
	if calls := blocks.retireCalls(); len(calls) != 1 || len(calls[0]) != 1 || calls[0][0].Action != string(a.Attempt.ID) {
		t.Errorf("engine received a missing attempt or repeated a healthy one: %+v", calls)
	}
	if err := o.do(func() error {
		keep = false
		o.noteRetirement(o.now)
		if err := o.retire(); err != nil {
			return err
		}
		if len(o.retireFaults) != 0 || len(o.retireRetry) != 0 || len(o.retireDelay) != 0 {
			t.Errorf("removed intent retained retry state: %v, %v, %v", o.retireFaults, o.retireRetry, o.retireDelay)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestOwnerRetirementKeepsFaultWaitAfterRepair(t *testing.T) {
	for _, cause := range []error{admission.ErrCorruptRecord, admission.ErrTransitionConflict} {
		t.Run(cause.Error(), func(t *testing.T) {
			p := withTestRegistry(t)
			f := newOwnerFixture(t)
			blocks := newFakeBlocks()
			o := f.start(executeOptions(f, blocks))
			mono := heldMono(t, o)
			c, a := unknownBlock(t, o, p, f, blocks, "192.0.2.105")
			retire := retireLedger
			setOwnerHook(t, o, &retireLedger, func(*store.AdmissionLedger, admission.ActionID) (admission.Candidate, admission.AttemptRecord, bool, error) {
				return admission.Candidate{}, admission.AttemptRecord{}, false, cause
			})
			f.host.advance(25 * time.Hour)
			mono.advance(25 * time.Hour)
			if err := o.do(o.turn); err != nil {
				t.Fatalf("first fault failed the turn: %v", err)
			}
			if got := o.status().Owner.RetirementError; !strings.Contains(got, cause.Error()) {
				t.Fatalf("first fault = %q, want %v", got, cause)
			}
			setOwnerHook(t, o, &retireLedger, retire)
			f.host.advance(retireRecheck - time.Nanosecond)
			mono.advance(retireRecheck - time.Nanosecond)
			if err := o.do(func() error {
				o.noteRetirement(o.now)
				return o.turn()
			}); err != nil {
				t.Fatal(err)
			}
			if attemptOf(t, o, c).Retired || len(blocks.retireCalls()) != 1 {
				t.Fatal("repair bypassed the damage recheck")
			}
			f.host.advance(time.Nanosecond)
			mono.advance(time.Nanosecond)
			if err := o.do(o.turn); err != nil {
				t.Fatal(err)
			}
			if !attemptOf(t, o, c).Retired || len(blocks.retireCalls()) != 2 {
				t.Fatal("repaired attempt did not retire at its recheck")
			}
			if err := o.do(func() error {
				if o.retireFaults[a.Attempt.ID] || o.retireDelay[a.Attempt.ID] != 0 || !o.retireRetry[a.Attempt.ID].IsZero() {
					t.Error("repaired attempt retained retry state")
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestOwnerRetirementSharesClockAndEngineBackoff(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	blocks := newFakeBlocks()
	o := f.start(executeOptions(f, blocks))
	mono := heldMono(t, o)
	c, _ := unknownBlock(t, o, p, f, blocks, "192.0.2.106")
	blocks.set(func(b *fakeBlocks) { b.retireErr = errors.New("fixture engine outage") })
	f.host.advance(25 * time.Hour)
	mono.advance(25 * time.Hour)
	for i, wait := range []time.Duration{time.Second, 2 * time.Second} {
		if err := o.do(func() error {
			if err := o.tick(); err != nil {
				return err
			}
			o.degraded = i == 0
			err := o.retire()
			if (i == 1) != (err != nil) {
				t.Errorf("pass %d: retirement report = %v", i, err)
			}
			o.reportRetirement(err)
			if o.retireWait != wait || !o.retireAt.Equal(mono.read().Add(wait)) {
				t.Errorf("pass %d: backoff = %v until %v, want %v", i, o.retireWait, o.retireAt, wait)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		if len(blocks.retireCalls()) != i || attemptOf(t, o, c).Retired {
			t.Fatal("degraded clock called the engine or an outage retired the attempt")
		}
		f.host.advance(wait)
		mono.advance(wait)
	}
	blocks.set(func(b *fakeBlocks) { b.retireErr = nil })
	if err := o.do(o.turn); err != nil {
		t.Fatal(err)
	}
	if !attemptOf(t, o, c).Retired {
		t.Fatal("recovery did not retire the attempt")
	}
}

func TestOwnerRetirementBacksOffUnreadableIntents(t *testing.T) {
	withTestRegistry(t)
	f := newOwnerFixture(t)
	o := f.start(executeOptions(f, newFakeBlocks()))
	mono := heldMono(t, o)
	scans := 0
	setOwnerHook(t, o, &unresolvedIntents, func(*store.AdmissionLedger) ([]admission.Intent, error) {
		scans++
		return nil, admission.ErrCorruptRecord
	})
	for pass := range 2 {
		if err := o.do(func() error {
			err := o.retire()
			if (pass == 0) != errors.Is(err, admission.ErrCorruptRecord) {
				t.Errorf("pass %d: intent damage error = %v", pass, err)
			}
			if !o.retirementWake(mono.read()).Equal(mono.read().Add(retireRecheck)) {
				t.Errorf("damaged intents have no recheck: %v", o.retirementWake(mono.read()))
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		mono.advance(retireRecheck - time.Nanosecond)
		if err := o.do(o.retire); err != nil {
			t.Errorf("damage repeated before recheck: %v", err)
		}
		if scans != pass+1 {
			t.Errorf("intent damage retried early: %d scans", scans)
		}
		mono.advance(time.Nanosecond)
	}
	setOwnerHook(t, o, &unresolvedIntents, func(*store.AdmissionLedger) ([]admission.Intent, error) {
		return nil, nil
	})
	if err := o.do(o.retire); err != nil {
		t.Fatal(err)
	}
	setOwnerHook(t, o, &unresolvedIntents, func(*store.AdmissionLedger) ([]admission.Intent, error) {
		return nil, admission.ErrCorruptRecord
	})
	if err := o.do(o.retire); !errors.Is(err, admission.ErrCorruptRecord) {
		t.Fatalf("new damage after recovery was hidden: %v", err)
	}
}

// backoffSteps is the wait a retirement retry follows while its cause
// lasts: one second, doubling to a minute.
var backoffSteps = []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second, 16 * time.Second, 32 * time.Second, time.Minute, time.Minute}

// While audit delivery or the ledger clock keeps refusing a retirement,
// each attempt is asked again after one second, doubling to a minute, so a
// long outage costs one engine check a minute rather than one a second
// (1.5c-3a review M2). Success clears the attempt's wait.
func TestOwnerRetirementBacksOffWhileTheLedgerRefuses(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	blocks := newFakeBlocks()
	o := f.start(executeOptions(f, blocks))
	mono := heldMono(t, o)
	a := retirementAttempt(t, o, p, f, "192.0.2.95", true)
	f.host.advance(2 * time.Hour)
	mono.advance(2 * time.Hour)
	for i, want := range backoffSteps {
		if err := o.do(func() error {
			if err := o.tick(); err != nil {
				return err
			}
			if err := o.retire(); err != nil {
				return err
			}
			if got := o.retireRetry[a.Attempt.ID].Sub(mono.read()); got != want {
				t.Errorf("pass %d: retry in %v, want %v", i, got, want)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		if calls := len(blocks.retireCalls()); calls != i+1 {
			t.Fatalf("pass %d: %d engine checks", i, calls)
		}
		f.host.advance(want)
		mono.advance(want)
	}
	if err := o.do(o.deliverAudit); err != nil {
		t.Fatal(err)
	}
	if err := o.do(func() error {
		if err := o.tick(); err != nil {
			return err
		}
		if err := o.retire(); err != nil {
			return err
		}
		if len(o.retireRetry) != 0 || len(o.retireDelay) != 0 {
			t.Errorf("retired attempt kept its wait: %v, %v", o.retireRetry, o.retireDelay)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if got := attemptOf(t, o, candidate(t, o, a.Attempt.Candidate)); !got.Retired {
		t.Fatalf("delivered audit did not let the attempt retire: %+v", got)
	}
}

// With an expired unknown and no engine to check it, the pass waits one
// second, doubling to a minute, instead of listing every intent each
// second (M2).
func TestOwnerRetirementBacksOffWithoutAnEngine(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	blocks := newFakeBlocks()
	opts := executeOptions(f, blocks)
	opts.Blocks = func() BlockEngine { return nil }
	o := f.start(opts)
	mono := heldMono(t, o)
	retirementAttempt(t, o, p, f, "192.0.2.96", true)
	f.host.advance(2 * time.Hour)
	mono.advance(2 * time.Hour)
	for i, want := range backoffSteps {
		if err := o.do(func() error {
			if err := o.tick(); err != nil {
				return err
			}
			if err := o.retire(); err != nil {
				return err
			}
			if got := o.retireAt.Sub(mono.read()); got != want {
				t.Errorf("pass %d: next pass in %v, want %v", i, got, want)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		f.host.advance(want)
		mono.advance(want)
	}
}

// A damaged record cannot be retired by retrying: the owner asks about it
// again a minute later and reports it once, so it does not fail every turn
// and slow all owner work (1.5c-3a review M1).
func TestOwnerRetirementReportsADamagedRecordOnce(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	blocks := newFakeBlocks()
	o := f.start(executeOptions(f, blocks))
	mono := heldMono(t, o)
	c, a := unknownBlock(t, o, p, f, blocks, "192.0.2.97")
	retire := retireLedger
	setOwnerHook(t, o, &retireLedger, func(*store.AdmissionLedger, admission.ActionID) (admission.Candidate, admission.AttemptRecord, bool, error) {
		return admission.Candidate{}, admission.AttemptRecord{}, false, admission.ErrCorruptRecord
	})
	f.host.advance(25 * time.Hour)
	mono.advance(25 * time.Hour)
	for pass := range 2 {
		if err := o.do(func() error {
			if err := o.tick(); err != nil {
				return err
			}
			err := o.retire()
			if (pass == 0) != errors.Is(err, admission.ErrCorruptRecord) {
				t.Errorf("pass %d: error %v; want the damage reported on the first pass only", pass, err)
			}
			if got := o.retireRetry[a.Attempt.ID].Sub(mono.read()); got != retireRecheck {
				t.Errorf("pass %d: retry in %v, want %v", pass, got, retireRecheck)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		if calls := len(blocks.retireCalls()); calls != pass+1 {
			t.Fatalf("pass %d: %d engine checks", pass, calls)
		}
		f.host.advance(retireRecheck)
		mono.advance(retireRecheck)
	}
	setOwnerHook(t, o, &retireLedger, retire)
	if err := o.do(func() error {
		if err := o.tick(); err != nil {
			return err
		}
		if err := o.retire(); err != nil {
			return err
		}
		if len(o.retireFaults) != 0 || len(o.retireRetry) != 0 {
			t.Errorf("retired attempt kept its fault: %v, %v", o.retireFaults, o.retireRetry)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if !attemptOf(t, o, c).Retired {
		t.Fatal("a repaired record did not retire")
	}
}

// A turn that fails after its retirement pass reports the pass's error
// apart, whether the schedule or the block batch fails: the turn fails
// with its own step's error and status keeps the retirement fault
// (1.5c-3a review M7, C4).
func TestOwnerTurnReportsItsRetirementErrorApart(t *testing.T) {
	for _, step := range []string{"schedule", "execute", "publish"} {
		t.Run(step, func(t *testing.T) {
			p := withTestRegistry(t)
			f := newOwnerFixture(t)
			blocks := newFakeBlocks()
			o := f.start(executeOptions(f, blocks))
			mono := heldMono(t, o)
			unknownBlock(t, o, p, f, blocks, "192.0.2.98")
			retireCause, stepCause := errors.New("fixture retirement failure"), errors.New("fixture "+step+" failure")
			retired := false
			setOwnerHook(t, o, &retireLedger, func(*store.AdmissionLedger, admission.ActionID) (admission.Candidate, admission.AttemptRecord, bool, error) {
				retired = true
				return admission.Candidate{}, admission.AttemptRecord{}, false, retireCause
			})
			f.host.advance(25 * time.Hour)
			mono.advance(25 * time.Hour)
			switch step {
			case "schedule":
				setOwnerHook(t, o, &scheduleLedger, func(*store.AdmissionLedger, admission.ScheduleLimits, map[admission.CandidateID]admission.Answer) ([]admission.Pick, error) {
					return nil, stepCause
				})
			case "publish":
				// The tick reads the snapshot too; fail only the read after
				// retirement ran.
				read := readSnapshot
				setOwnerHook(t, o, &readSnapshot, func(l *store.AdmissionLedger) (*admission.QueueSnapshot, error) {
					if retired {
						return nil, stepCause
					}
					return read(l)
				})
			default:
				if err := o.do(o.tick); err != nil {
					t.Fatal(err)
				}
				queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.99")
				setOwnerHook(t, o, &executeLedger, func(*store.AdmissionLedger, []admission.ActionID) ([]admission.Intent, bool, error) {
					return nil, false, stepCause
				})
			}
			err := o.do(o.turn)
			if errors.Is(err, retireCause) || !errors.Is(err, stepCause) {
				t.Fatalf("turn error = %v; want the %s failure alone", err, step)
			}
			if got := o.status().Owner.RetirementError; !strings.Contains(got, retireCause.Error()) {
				t.Fatalf("retirement error = %q", got)
			}
		})
	}
}

func TestOwnerRetirementLedgerBackoffKeepsWakeAndScanGate(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	blocks := newFakeBlocks()
	o := f.start(executeOptions(f, blocks))
	mono := heldMono(t, o)
	a := retirementAttempt(t, o, p, f, "192.0.2.100", true)
	list, scans := unresolvedIntents, 0
	setOwnerHook(t, o, &unresolvedIntents, func(l *store.AdmissionLedger) ([]admission.Intent, error) {
		scans++
		return list(l)
	})
	f.host.advance(2 * time.Hour)
	mono.advance(2 * time.Hour)
	for i, wait := range backoffSteps {
		if err := o.do(func() error {
			o.scheduleDue = true
			o.schedule()
			if !o.wakeAt.Equal(mono.read().Add(wait)) {
				t.Errorf("pass %d lost its wake: %v", i, o.wakeAt)
			}
			return o.scheduleErr
		}); err != nil {
			t.Fatal(err)
		}
		f.host.advance(wait - time.Nanosecond)
		mono.advance(wait - time.Nanosecond)
		if err := o.do(func() error {
			before := scans
			if err := o.tick(); err != nil {
				return err
			}
			if err := o.retire(); err != nil {
				return err
			}
			if scans != before || len(blocks.retireCalls()) != i+1 {
				t.Errorf("backoff rescanned intents or checked the engine early")
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		f.host.advance(time.Nanosecond)
		mono.advance(time.Nanosecond)
	}
	if err := o.do(o.deliverAudit); err != nil {
		t.Fatal(err)
	}
	if err := o.do(func() error { o.schedule(); return o.scheduleErr }); err != nil {
		t.Fatal(err)
	}
	if !attemptOf(t, o, candidate(t, o, a.Attempt.Candidate)).Retired {
		t.Fatal("audit recovery stranded an expired unknown without an arrival")
	}
	if err := o.do(func() error {
		if len(o.retireRetry) != 0 || len(o.retireDelay) != 0 || len(o.retireFaults) != 0 || o.retireWait != 0 || !o.retireAt.IsZero() || !o.wakeAt.IsZero() {
			t.Error("successful retirement retained a delay or wake")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// A dry-run policy still retires earlier unknown blocks; a forecast
// failure is the turn's error and the retirement fault stays apart.
func TestOwnerForecastTurnReportsItsRetirementErrorApart(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	blocks := newFakeBlocks()
	o, r, mono := policyOwner(t, f, blocks, validPolicy(1))
	unknownBlock(t, o, p, f, blocks, "192.0.2.97")
	r.publish(dryPolicy(2))
	if err := o.Reload(); err != nil {
		t.Fatal(err)
	}
	retireCause, forecastCause := errors.New("fixture retirement failure"), errors.New("fixture forecast failure")
	setOwnerHook(t, o, &retireLedger, func(*store.AdmissionLedger, admission.ActionID) (admission.Candidate, admission.AttemptRecord, bool, error) {
		return admission.Candidate{}, admission.AttemptRecord{}, false, retireCause
	})
	setOwnerHook(t, o, &previewLedger, func(*store.AdmissionLedger, map[admission.CandidateID]admission.Answer) ([]admission.Pick, error) {
		return nil, forecastCause
	})
	f.host.advance(25 * time.Hour)
	mono.advance(25 * time.Hour)
	err := o.do(o.turn)
	if errors.Is(err, retireCause) || !errors.Is(err, forecastCause) {
		t.Fatalf("turn error = %v; want the forecast failure alone", err)
	}
	if got := o.status().Owner.RetirementError; !strings.Contains(got, retireCause.Error()) {
		t.Fatalf("retirement error = %q", got)
	}
}
