package admissionowner

import (
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
)

// A forecast leaves no genuine safety state in the ledger: every charge
// is the imported legacy hour's and no intent holds an address. A build
// that refuses this ledger after a dry run forgets nothing legacy blocking
// does not keep itself.
func TestForecastLeavesNoGenuineState(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	f.legacy(`{"ips":[],"blocks_this_hour":12,"hour_key":"2026-10-04T12"}`)
	o, _, mono := policyOwner(t, f, newFakeBlocks(), dryPolicy(1))
	forecast, _ := queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.10")
	turn(t, o)
	mono.advance(batchEvery)
	turn(t, o)
	if c := candidate(t, o, forecast); c.State != admission.StateDryRun || c.Attempts != 0 {
		t.Fatalf("forecast pick = %+v", c)
	}
	var charges []admission.Charge
	var intents []admission.Intent
	if err := o.do(func() (err error) {
		if _, charges, err = o.ledger.CeilingSnapshot(); err != nil {
			return err
		}
		intents, err = o.ledger.UnresolvedIntents()
		return err
	}); err != nil {
		t.Fatal(err)
	}
	var legacy uint32
	for _, c := range charges {
		var a admission.AttemptRecord
		err := o.do(func() (err error) { a, err = o.ledger.Attempt(c.Action); return err })
		switch {
		case err != nil:
			end := time.Date(2026, 10, 4, 13, 0, 0, 0, time.UTC)
			reason, ok := admission.ReasonOf(err)
			if !ok || reason != admission.ReasonInvalid || c.Action != admission.LegacyActionID(end, 1) || c.Cost != 12 {
				t.Fatalf("unexpected attempt lookup failure for charge %+v: %v", c, err)
			}
			legacy += c.Cost
		default:
			t.Fatalf("charge %s belongs to a genuine attempt %+v", c.Action, a)
		}
	}
	if legacy != 12 || len(intents) != 0 {
		t.Fatalf("legacy units %d, intents %+v", legacy, intents)
	}
}

// Status says the owner executes only with an engine and a live policy:
// a forecasting owner and an owner without an engine do not.
func TestOwnerExecutesOnlyUnderALivePolicy(t *testing.T) {
	for _, tc := range []struct {
		name        string
		engine, dry bool
		want        bool
	}{
		{"live", true, false, true},
		{"dry run", true, true, false},
		{"no engine", false, false, false},
		{"no engine dry run", false, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			withTestRegistry(t)
			f := newOwnerFixture(t)
			first := validPolicy(1)
			first.DryRun = tc.dry
			r := &policyReader{p: first}
			opts := previewOptions(f)
			if tc.engine {
				opts = executeOptions(f, newFakeBlocks())
			}
			opts.Policy = r.read
			o := f.start(opts)
			turn(t, o)
			if s := o.status(); s.Owner == nil || s.Owner.Executing != tc.want {
				t.Fatalf("owner status = %+v, want executing %v", s.Owner, tc.want)
			}
		})
	}
}

// Stored real unknowns survive a restart into an owner without an engine.
// Their expiry must not let it retire them.
func TestPreviewOnlyOwnerLeavesStoredUnknownsAlone(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	blocks := newFakeBlocks()
	o := f.start(executeOptions(f, blocks))
	c, _ := unknownBlock(t, o, p, f, blocks, "192.0.2.10")
	o.Stop()
	f.host.advance(25 * time.Hour)
	o = f.start(previewOptions(f))
	turn(t, o)
	if got := attemptOf(t, o, c); got.Retired || got.State != admission.StateUnknown {
		t.Fatalf("stored unknown changed: %+v", got)
	}
}
