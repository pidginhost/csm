package admissionowner

import (
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/firewall"
	"github.com/pidginhost/csm/internal/store"
)

// A policy refusal must not turn a retained live fault into permission to
// probe or repair the engine, even when its probe deadline is due.
func TestOwnerRefusedPolicyLeavesEngineHoldAlone(t *testing.T) {
	for _, dry := range []bool{false, true} {
		t.Run(fmt.Sprintf("dry_run=%t", dry), func(t *testing.T) {
			p := withTestRegistry(t)
			f := newOwnerFixture(t)
			blocks := newFakeBlocks()
			blocks.results["192.0.2.10"] = firewall.BlockResult{Effect: firewall.BlockUnknown, Err: firewall.ErrBlockBatchState}
			o, r, mono := policyOwner(t, f, blocks, validPolicy(1))
			queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.10")
			turn(t, o)
			if executionHeld(t, o) == "" {
				t.Fatal("fixture: no engine hold")
			}
			if dry {
				r.publish(dryPolicy(2))
				if err := o.Reload(); err != nil {
					t.Fatal(err)
				}
				turn(t, o)
			}
			next := validPolicy(3)
			next.DryRun, next.AskVerdict = dry, nil
			r.publish(next)
			if err := o.Reload(); !errors.Is(err, ErrPolicy) {
				t.Fatalf("refused reload = %v", err)
			}
			id, _ := queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.11")
			selections := 0
			schedule := scheduleLedger
			setOwnerHook(t, o, &scheduleLedger, func(l *store.AdmissionLedger, lim admission.ScheduleLimits, answers map[admission.CandidateID]admission.Answer) ([]admission.Pick, error) {
				selections++
				return schedule(l, lim, answers)
			})
			for range 3 {
				mono.advance(maxProbeWait)
				if err := o.do(func() error { o.schedule(); return o.scheduleErr }); err != nil {
					t.Fatal(err)
				}
			}
			if c := candidate(t, o, id); c.State != admission.StateQueued || c.Reason != admission.ReasonEngineUnavailable || c.Attempts != 0 {
				t.Fatalf("held pick = %+v", c)
			}
			checks, applies := blocks.calls()
			if len(checks) != 1 || len(applies) != 1 || blocks.marks != 0 || blocks.stateProbes != 0 || selections != 1 {
				t.Fatalf("refused policy: %d checks, %d applies, %d repairs, %d probes, %d selections", len(checks), len(applies), blocks.marks, blocks.stateProbes, selections)
			}
			if err := o.do(func() error {
				if !errors.Is(o.execHold, firewall.ErrBlockBatchState) {
					return fmt.Errorf("engine hold was lost: %v", o.execHold)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// Dry-run suspends probes without losing their hold. Publishing a live
// epoch must resume them even with no arrival, reload or queued deadline.
func TestOwnerResumesLiveProbesAfterIdleForecast(t *testing.T) {
	f := newOwnerFixture(t)
	blocks := newFakeBlocks()
	o, r, mono := policyOwner(t, f, blocks, validPolicy(1))
	if err := o.do(func() error { o.hold(firewall.ErrBlockBatchState, false); return nil }); err != nil {
		t.Fatal(err)
	}
	r.publish(dryPolicy(2))
	if err := o.Reload(); err != nil {
		t.Fatal(err)
	}
	if err := o.do(func() error { o.schedule(); return o.scheduleErr }); err != nil {
		t.Fatal(err)
	}
	if forecastOf(t, o) == nil || blocks.marks != 0 || blocks.stateProbes != 0 {
		t.Fatal("fixture: idle forecast did not retain the hold")
	}
	r.publish(validPolicy(3))
	mono.advance(time.Second)
	if err := o.do(func() error { o.schedule(); return o.scheduleErr }); err != nil {
		t.Fatal(err)
	}
	if forecastOf(t, o) != nil || blocks.marks != 1 || blocks.stateProbes != 1 || executionHeld(t, o) != "" {
		t.Fatalf("live publication: %d repairs, %d probes, held %q", blocks.marks, blocks.stateProbes, executionHeld(t, o))
	}
}

// A live publication during a forecast cannot change any pick's mode.
// Reload waits for all dry-run endings before admitting a new live turn.
func TestOwnerForecastKeepsItsPolicyAcrossALivePublication(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	blocks := newFakeBlocks()
	reached, release := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	var once sync.Once
	first := dryPolicy(1)
	first.Expiry = func(admission.Candidate) time.Duration {
		if calls.Add(1) == 1 {
			close(reached)
			<-release
		}
		return time.Hour
	}
	o, r, _ := policyOwner(t, f, blocks, first)
	t.Cleanup(func() { once.Do(func() { close(release) }) })
	var ids []admission.CandidateID
	for _, ip := range []string{"192.0.2.10", "192.0.2.11"} {
		id, _ := queuedAt(t, o, p, f.host, admission.SeverityHigh, ip)
		ids = append(ids, id)
	}
	turned := make(chan error, 1)
	go func() { turned <- o.do(o.turn) }()
	<-reached
	r.publish(validPolicy(2))
	reloaded := make(chan error, 1)
	go func() { reloaded <- o.Reload() }()
	select {
	case err := <-reloaded:
		t.Fatalf("reload returned during the forecast: %v", err)
	default:
	}
	once.Do(func() { close(release) })
	if err := <-turned; err != nil {
		t.Fatal(err)
	}
	if err := <-reloaded; err != nil {
		t.Fatal(err)
	}
	for _, id := range ids {
		if c := candidate(t, o, id); c.State != admission.StateDryRun || c.Attempts != 0 {
			t.Fatalf("forecast pick after live publication = %+v", c)
		}
	}
	checks, applies := blocks.calls()
	if len(checks) != 0 || len(applies) != 0 || blocks.marks != 0 || blocks.stateProbes != 0 || liveUsed(t, o) != 0 || len(pendingAudit(t, o)) != 0 {
		t.Fatal("the dry-run turn reached live enforcement accounting or the engine")
	}
	if len(blocks.snapshots) != 1 || len(blocks.snapshots[0]) != 2 {
		t.Fatalf("forecast snapshots = %+v", blocks.snapshots)
	}
	for _, m := range blocks.snapshots[0] {
		if !m.ExpiresAt.Equal(f.host.now().Add(time.Hour)) {
			t.Fatalf("forecast used the new expiry: %+v", m)
		}
	}
	live, _ := queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.12")
	turn(t, o)
	if c := candidate(t, o, live); c.State != admission.StateVerified || c.Attempts != 1 {
		t.Fatalf("pick after reload = %+v", c)
	}
}

// Repeating an ending with its original speculative delta must not
// overwrite later committed admissions or count the original pick twice.
func TestOwnerForecastIgnoresAnUnchangedEnding(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	blocks := newFakeBlocks()
	o, _, _ := policyOwner(t, f, blocks, dryPolicy(1))
	queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.10")
	queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.11")
	var first execPick
	var change *shadowChange
	end := endDryRunLedger
	setOwnerHook(t, o, &endDryRunLedger, func(l *store.AdmissionLedger, pick admission.CandidateID) (admission.Candidate, bool, error) {
		if change == nil {
			c, err := l.Candidate(pick)
			if err != nil {
				return admission.Candidate{}, false, err
			}
			first = execPick{pick: admission.Pick{ID: pick, Lane: admission.LaneGeneral}, c: c}
			addr, _ := c.Key.Target.Addr()
			_, change, err = o.shadow.admit(addr.String(), admission.KindBlockIP, f.host.now().Add(24*time.Hour), []admission.Lane{admission.LaneGeneral}, o.now, firewall.BlockAdmission{})
			if err != nil {
				return admission.Candidate{}, false, err
			}
		}
		return end(l, pick)
	})
	turn(t, o)
	before := forecastOf(t, o)
	if before.picks[predictCapacityAdmit] != 2 || len(before.entries) != 2 || change == nil {
		t.Fatalf("fixture: forecast = %+v, change = %+v", before, change)
	}
	// Restore the real ending so the replay keeps its captured delta.
	setOwnerHook(t, o, &endDryRunLedger, end)
	if err := o.do(func() error { return o.endForecast(first, predictCapacityAdmit, change) }); err != nil {
		t.Fatal(err)
	}
	after := forecastOf(t, o)
	if after.ceiling != before.ceiling || after.picks != before.picks || len(after.entries) != len(before.entries) {
		t.Fatalf("unchanged ending changed the forecast: before %+v, after %+v", before, after)
	}
	if n := outcomes(ledgerStatus(t, o), admission.DispositionDryRun); n != 2 || liveUsed(t, o) != 0 || len(pendingAudit(t, o)) != 0 {
		t.Fatalf("unchanged ending changed durable accounting: %d outcomes", n)
	}
}
