package admissionowner

import (
	"errors"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
)

// A forecast session starts from real state without preview state. Its
// ceiling leaves out an earlier preview's charge and keeps the imported
// legacy hour, and an address a preview answered is forecast again on its
// next observation. Back under a live policy, previews answer their
// episodes again.
func TestForecastSessionLeavesPreviewStateOut(t *testing.T) {
	withLiveExecution(t, false)
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	f.legacy(`{"ips":[],"blocks_this_hour":12,"hour_key":"2026-10-04T12"}`)
	o, r, mono := policyOwner(t, f, newFakeBlocks(), validPolicy(1))
	first := observe(t, o, p, f, "192.0.2.10", "offset=1")
	turn(t, o)
	if c := candidate(t, o, first); c.State != admission.StateObserved {
		t.Fatalf("pick under a live policy = %+v", c)
	}
	real := ceiling(t, o)
	if real.General.Used != 13 {
		t.Fatalf("real general use = %d, want the legacy 12 and the preview", real.General.Used)
	}
	r.publish(dryPolicy(2))
	mono.advance(batchEvery)
	turn(t, o)
	if s := forecastOf(t, o); s == nil || s.ceiling.General.Used != 12 || s.ceiling.General.Credit <= real.General.Credit {
		t.Fatalf("forecast seed = %+v, real %+v", s, real.General)
	}
	if err := o.do(func() error {
		charges := o.shadow.charges
		end := time.Date(2026, 10, 4, 13, 0, 0, 0, time.UTC)
		if len(charges) != 1 || charges[0].Action != admission.LegacyActionID(end, 1) || charges[0].Cost != 12 || charges[0].Lane != admission.LaneGeneral {
			return errors.New("forecast seed lost the retained legacy-hour charge")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	f.host.advance(time.Second)
	again := observe(t, o, p, f, "192.0.2.10", "offset=2")
	mono.advance(batchEvery)
	turn(t, o)
	if c := candidate(t, o, again); c.State != admission.StateDryRun || c.Key.Generation != 2 {
		t.Fatalf("previewed address while forecasting = %+v", c)
	}

	r.publish(validPolicy(3))
	mono.advance(batchEvery)
	turn(t, o)
	f.host.advance(time.Second)
	third := observe(t, o, p, f, "192.0.2.10", "offset=3")
	mono.advance(batchEvery)
	turn(t, o)
	if c := candidate(t, o, third); c.State != admission.StateObserved || c.Key.Generation != 3 {
		t.Fatalf("pick back under a live policy = %+v", c)
	}
	f.host.advance(time.Second)
	submitObservation(t, o, p, "192.0.2.10", "offset=4", f.host.now())
	if err := o.do(o.drain); err != nil {
		t.Fatal(err)
	}
	for _, c := range queuedCandidates(t, o) {
		if c.Key.Target.Key() == "ip:192.0.2.10" {
			t.Fatalf("a preview no longer answers its episode: %+v", c)
		}
	}
}

// A restart straight into dry run forecasts an address previewed before
// it: the new owner tells the ledger before its first drain.
func TestForecastAfterARestartLeavesPreviewsOut(t *testing.T) {
	withLiveExecution(t, false)
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	blocks := newFakeBlocks()
	o, _, _ := policyOwner(t, f, blocks, validPolicy(1))
	first := observe(t, o, p, f, "192.0.2.10", "offset=1")
	turn(t, o)
	if c := candidate(t, o, first); c.State != admission.StateObserved {
		t.Fatalf("pick under a live policy = %+v", c)
	}
	o.Stop()
	o, _, mono := policyOwner(t, f, blocks, dryPolicy(1))
	f.host.advance(time.Second)
	again := observe(t, o, p, f, "192.0.2.10", "offset=2")
	mono.advance(batchEvery)
	turn(t, o)
	if c := candidate(t, o, again); c.State != admission.StateDryRun || c.Key.Generation != 2 {
		t.Fatalf("previewed address after a restart into dry run = %+v", c)
	}
}

// A refused refresh leaves forecasting, so stored previews answer again.
// A later valid dry-run policy must turn that placement rule off again.
func TestForecastPreviewRuleFollowsRefusedPolicies(t *testing.T) {
	withLiveExecution(t, false)
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	o, r, mono := policyOwner(t, f, newFakeBlocks(), validPolicy(1))
	first := observe(t, o, p, f, "192.0.2.10", "offset=1")
	turn(t, o)
	if c := candidate(t, o, first); c.State != admission.StateObserved {
		t.Fatalf("preview fixture = %+v", c)
	}
	r.publish(dryPolicy(2))
	if err := o.Reload(); err != nil {
		t.Fatal(err)
	}
	invalid := dryPolicy(3)
	invalid.Allows = nil
	r.publish(invalid)
	if err := o.Reload(); !errors.Is(err, ErrPolicy) {
		t.Fatalf("invalid refresh = %v", err)
	}
	f.host.advance(time.Second)
	submitObservation(t, o, p, "192.0.2.10", "offset=2", f.host.now())
	if err := o.do(o.drain); err != nil {
		t.Fatal(err)
	}
	if queued := queuedCandidates(t, o); len(queued) != 0 {
		t.Fatalf("a refused policy left preview answers disabled: %+v", queued)
	}
	if c := candidate(t, o, first); c.State != admission.StateObserved {
		t.Fatalf("refresh rewrote the preview: %+v", c)
	}
	r.publish(dryPolicy(4))
	if err := o.Reload(); err != nil {
		t.Fatal(err)
	}
	f.host.advance(time.Second)
	again := observe(t, o, p, f, "192.0.2.10", "offset=3")
	mono.advance(batchEvery)
	turn(t, o)
	if c := candidate(t, o, again); c.State != admission.StateDryRun || c.Key.Generation != 2 {
		t.Fatalf("restored forecast = %+v", c)
	}
}

// A comparison-only owner does not read even an available dry-run policy,
// and its previews keep answering after startup and reload.
func TestComparisonOnlyOwnerKeepsPreviewAnswers(t *testing.T) {
	withLiveExecution(t, false)
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	r := &policyReader{p: dryPolicy(1)}
	opts := f.options()
	opts.Policy = r.read
	opts.Expiry = func(admission.Candidate) time.Duration { return time.Hour }
	o := f.start(opts)
	first := observe(t, o, p, f, "192.0.2.10", "offset=1")
	turn(t, o)
	if c := candidate(t, o, first); c.State != admission.StateObserved {
		t.Fatalf("comparison fixture = %+v", c)
	}
	if err := o.Reload(); err != nil {
		t.Fatal(err)
	}
	f.host.advance(time.Second)
	submitObservation(t, o, p, "192.0.2.10", "offset=2", f.host.now())
	if err := o.do(o.drain); err != nil {
		t.Fatal(err)
	}
	if queued := queuedCandidates(t, o); len(queued) != 0 || r.count() != 0 || forecastOf(t, o) != nil {
		t.Fatalf("comparison read policy or stopped answering: queued=%+v reads=%d", queued, r.count())
	}
}
