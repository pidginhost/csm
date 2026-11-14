package admissionowner

import (
	"sync/atomic"
	"testing"
)

// The response funnels read whether the owner applies block picks before
// they mint: legacy leaves a block to admission only when an engine, live
// execution and a live policy are all present, and never once it stops.
func TestOwnerPublishesWhetherItExecutesBlocks(t *testing.T) {
	for _, tc := range []struct {
		name                 string
		live, dryRun, engine bool
		want                 bool
	}{
		{"live", true, false, true, true},
		{"dry_run", true, true, true, false},
		{"preview_only", false, false, true, false},
		{"no_engine", true, false, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			withLiveExecution(t, tc.live)
			f := newOwnerFixture(t)
			opts := previewOptions(f)
			if tc.engine {
				opts = executeOptions(f, newFakeBlocks())
			}
			r := &policyReader{p: validPolicy(1)}
			r.p.DryRun = tc.dryRun
			opts.Policy = r.read
			o := f.start(opts)
			if err := o.do(func() error { return nil }); err != nil {
				t.Fatal(err)
			}
			if got := o.ExecutesBlocks(); got != tc.want {
				t.Fatalf("ExecutesBlocks() = %v, want %v", got, tc.want)
			}
			o.Stop()
			if o.ExecutesBlocks() {
				t.Fatal("a stopped owner still executes blocks")
			}
		})
	}
}

// A newer dry-run policy stops block execution at the next turn boundary,
// so funnels hand blocks back to legacy from then on.
func TestOwnerStopsExecutingBlocksUnderANewerDryRunPolicy(t *testing.T) {
	f := newOwnerFixture(t)
	opts := executeOptions(f, newFakeBlocks())
	r := &policyReader{p: validPolicy(1)}
	opts.Policy = r.read
	o := f.start(opts)
	if err := o.do(func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	if !o.ExecutesBlocks() {
		t.Fatal("a live owner does not execute blocks")
	}
	p := validPolicy(2)
	p.DryRun = true
	r.publish(p)
	turn(t, o)
	if o.ExecutesBlocks() {
		t.Fatal("a dry-run policy still executes blocks")
	}
}

// The provider can lose its engine between policy installs. New hand-offs
// stay legacy until it returns; already accepted work stays owned.
func TestOwnerExecutionTracksEngineAvailability(t *testing.T) {
	f := newOwnerFixture(t)
	blocks := newFakeBlocks()
	opts := executeOptions(f, blocks)
	var available atomic.Bool
	opts.Blocks = func() BlockEngine {
		if available.Load() {
			return blocks
		}
		return nil
	}
	o := f.start(opts)
	if o.ExecutesBlocks() {
		t.Fatal("an owner whose provider returns nil executes blocks")
	}
	available.Store(true)
	if !o.ExecutesBlocks() {
		t.Fatal("an owner with an available engine does not execute blocks")
	}
	available.Store(false)
	if o.ExecutesBlocks() {
		t.Fatal("an owner whose engine disappeared still executes blocks")
	}
	available.Store(true)
	o.Stop()
	if o.ExecutesBlocks() {
		t.Fatal("a stopped owner with an available engine executes blocks")
	}
}

// A refused newer policy holds execution: work the owner already accepted
// waits for a valid policy, but new hand-offs keep their legacy block until
// one is installed.
func TestOwnerLeavesNewBlocksToLegacyDuringAPolicyHold(t *testing.T) {
	f := newOwnerFixture(t)
	opts := executeOptions(f, newFakeBlocks())
	r := &policyReader{p: validPolicy(1)}
	opts.Policy = r.read
	o := f.start(opts)
	if !o.ExecutesBlocks() {
		t.Fatal("a live owner does not execute blocks")
	}
	refused := validPolicy(2)
	refused.BlockExpiry = 0
	r.publish(refused)
	turn(t, o)
	if o.ExecutesBlocks() {
		t.Fatal("an owner holding a refused policy takes new blocks")
	}
	r.publish(validPolicy(3))
	turn(t, o)
	if !o.ExecutesBlocks() {
		t.Fatal("a valid newer policy did not resume block execution")
	}
}
