package admissionowner

import (
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/firewall"
)

// Missing or changed block rules refuse a batch before anything is written
// or sent: execution holds until a state probe sees the rules again, and
// no repair runs.
func TestOwnerMissingBlockRulesHoldWithoutApplyFault(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	blocks := newFakeBlocks()
	blocks.applyErr = firewall.ErrBlockRules
	o := f.start(executeOptions(f, blocks))
	mono := heldMono(t, o)
	id, _ := queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.120")
	if err := o.do(o.turn); err != nil {
		t.Fatal(err)
	}
	if c := candidate(t, o, id); c.Attempts != 1 || c.State != admission.StateQueued {
		t.Fatalf("refused apply = %+v", c)
	}
	if got := o.Status().Owner; got.ExecutionHeldBy != "firewall" || !strings.Contains(got.ExecutionHeld, firewall.ErrBlockRules.Error()) {
		t.Fatalf("missing rules status = %+v", got)
	}
	blocks.set(func(b *fakeBlocks) { b.checkErr = firewall.ErrBlockRules })
	mono.advance(time.Second)
	if err := o.do(o.turn); err != nil {
		t.Fatal(err)
	}
	if executionHeld(t, o) == "" {
		t.Fatal("missing rules released execution")
	}
	blocks.set(func(b *fakeBlocks) { b.checkErr, b.applyErr = nil, nil })
	mono.advance(2 * time.Second)
	if err := o.do(o.turn); err != nil {
		t.Fatal(err)
	}
	if got := o.Status().Owner; got.ExecutionHeld != "" || got.ExecutionHeldBy != "" {
		t.Fatalf("restored rules kept execution held: %+v", got)
	}
	blocks.set(func(b *fakeBlocks) {
		if b.marks != 0 {
			t.Fatalf("restored rules ran %d repairs", b.marks)
		}
	})
}
