package admissionowner

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/firewall"
)

// A window can start after member checks but before apply. Its refusal
// proves nothing was sent, so ending the window needs only a state probe,
// even while the charged attempt is still waiting for its retry.
func TestOwnerConfirmationAtApplyClearsOnIdleProbe(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	blocks := newFakeBlocks()
	blocks.applyErr = firewall.ErrConfirmPending
	o := f.start(executeOptions(f, blocks))
	mono := heldMono(t, o)
	id, _ := queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.110")
	if err := o.do(o.turn); err != nil {
		t.Fatal(err)
	}
	if c := candidate(t, o, id); c.Attempts != 1 || c.State != admission.StateQueued {
		t.Fatalf("refused apply = %+v", c)
	}
	if got := o.Status().Owner; got.ExecutionHeldBy != "firewall" || !strings.Contains(got.ExecutionHeld, firewall.ErrConfirmPending.Error()) {
		t.Fatalf("pending window status = %+v", got)
	}

	// The first probe still sees the window. It must not repair state.
	blocks.set(func(b *fakeBlocks) { b.checkErr = firewall.ErrConfirmPending })
	mono.advance(time.Second)
	if err := o.do(o.turn); err != nil {
		t.Fatal(err)
	}
	if executionHeld(t, o) == "" {
		t.Fatal("an open window released execution")
	}
	blocks.set(func(b *fakeBlocks) { b.checkErr, b.applyErr = nil, nil })
	mono.advance(2 * time.Second)
	if err := o.do(o.turn); err != nil {
		t.Fatal(err)
	}
	checks, applies := blocks.calls()
	if got := o.Status().Owner; got.ExecutionHeld != "" || got.ExecutionHeldBy != "" {
		t.Fatalf("a settled window kept idle execution held: %+v", got)
	}
	blocks.set(func(b *fakeBlocks) {
		if len(checks) != 1 || len(applies) != 1 || b.marks != 0 || b.stateProbes != 2 {
			t.Fatalf("window recovery: checks=%d applies=%d repairs=%d probes=%d", len(checks), len(applies), b.marks, b.stateProbes)
		}
	})
	for _, ip := range []string{"192.0.2.113", "192.0.2.114"} {
		queuedAt(t, o, p, f.host, admission.SeverityHigh, ip)
	}
	if err := o.do(o.turn); err != nil {
		t.Fatal(err)
	}
	if _, applies := blocks.calls(); len(applies) != 2 || len(applies[1]) != 2 {
		t.Fatalf("a settled window limited the next batch to an apply probe: %v", applies)
	}
}

// A window that interrupts an apply-fault probe must not replace the
// original fault: only a later one-member apply can prove that recovered.
func TestOwnerConfirmationPreservesEarlierApplyFault(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	blocks := newFakeBlocks()
	fault := errors.New("apply transport unavailable")
	blocks.applyErr = fault
	o := f.start(executeOptions(f, blocks))
	mono := heldMono(t, o)
	queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.111")
	if err := o.do(o.turn); err != nil {
		t.Fatal(err)
	}
	queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.112")
	blocks.set(func(b *fakeBlocks) { b.applyErr = firewall.ErrConfirmPending })
	mono.advance(time.Second)
	if err := o.do(o.turn); err != nil {
		t.Fatal(err)
	}
	blocks.set(func(b *fakeBlocks) { b.applyErr = nil })
	mono.advance(2 * time.Second)
	if err := o.do(o.turn); err != nil {
		t.Fatal(err)
	}
	if held := executionHeld(t, o); !strings.Contains(held, fault.Error()) || strings.Contains(held, firewall.ErrConfirmPending.Error()) {
		t.Fatalf("idle recovery lost the original apply fault: %q", held)
	}
	for _, ip := range []string{"192.0.2.115", "192.0.2.116"} {
		queuedAt(t, o, p, f.host, admission.SeverityHigh, ip)
	}
	mono.advance(4 * time.Second)
	if err := o.do(o.turn); err != nil {
		t.Fatal(err)
	}
	if _, applies := blocks.calls(); len(applies) != 3 || len(applies[2]) != 1 || executionHeld(t, o) != "" {
		t.Fatalf("earlier fault recovery: applies=%v held=%q", applies, executionHeld(t, o))
	}
}
