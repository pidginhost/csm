package admissionowner

import (
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
)

// While the firewall's first start runs, a live owner has no engine yet.
// Queued block work waits for it without a deferral or a notice; once that
// start ends without an engine, the missing engine withholds the work and
// says so; an engine that arrives later runs it.
func TestOwnerWaitsQuietlyForTheEngineToStart(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	sink := &noticeSink{}
	blocks := newFakeBlocks()
	starting, up := true, false
	opts := executeOptions(f, blocks)
	opts.Blocks = func() BlockEngine {
		if !up {
			return nil
		}
		return blocks
	}
	opts.EngineStarting = func() bool { return starting }
	opts.Deliver = sink.deliver
	o := f.start(opts)
	mono := heldMono(t, o)
	id, _ := queuedAt(t, o, p, f.host, admission.SeverityCritical, "192.0.2.10")
	for range 3 {
		turn(t, o)
		mono.advance(maxProbeWait)
	}
	o.notices.cycle()
	if c := candidate(t, o, id); c.State != admission.StateQueued || c.Reason != 0 || sink.count() != 0 {
		t.Fatalf("during the engine's start: candidate %v/%v, %d notices; want queued, no reason, none", c.State, c.Reason, sink.count())
	}
	if held := executionHeld(t, o); held == "" {
		t.Fatal("a missing engine did not hold execution")
	}
	starting = false
	turn(t, o)
	o.notices.cycle()
	if c := candidate(t, o, id); c.State != admission.StateQueued || c.Reason != admission.ReasonEngineUnavailable {
		t.Fatalf("after a failed start: candidate %v/%v; want queued engine_unavailable", c.State, c.Reason)
	}
	if sink.count() != 1 || sink.lastPreview() {
		t.Fatalf("after a failed start: %d notices, preview %v; want one live notice", sink.count(), sink.lastPreview())
	}
	up = true
	for range 3 {
		mono.advance(maxProbeWait + time.Second)
		turn(t, o)
	}
	if c := candidate(t, o, id); c.State != admission.StateVerified {
		t.Fatalf("with the engine: candidate %+v; want verified", c)
	}
	if _, applied := blocks.calls(); len(applied) != 1 {
		t.Fatalf("applies = %d, want 1", len(applied))
	}
}
