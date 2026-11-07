package admissionowner

import (
	"testing"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/firewall"
)

// A fresh attack of the same tier, once the only general slot's block is
// past its 30-minute hold, rotates that block out end to end: the engine
// receives the claimed victim, the ledger charges the new block, and the
// rotated block holds no slot (spec 5.6, 7.1 rotation liveness).
func TestOwnerRotatesAnEqualTierBlock(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	blocks := newFakeBlocks()
	// Three slots, one held by an operator block: one general, one reserved.
	blocks.limit, blocks.temp = 3, 1
	blocks.afterApply = func(b *fakeBlocks) { b.temp, b.admitted = 2, 1 }
	o := f.start(executeOptions(f, blocks))
	mono := heldMono(t, o)
	first := observe(t, o, p, f, "192.0.2.10", "offset=1")
	turn(t, o)
	victim := attemptOf(t, o, candidate(t, o, first))
	if victim.State != admission.StateVerified {
		t.Fatalf("the first block is %+v", victim)
	}
	mono.advance(admission.RotationHold)
	f.host.advance(admission.RotationHold)
	turn(t, o)
	blocks.set(func(b *fakeBlocks) {
		b.results["192.0.2.11"] = firewall.BlockResult{Effect: firewall.BlockApplied, Victim: firewall.VictimRemoved}
	})
	used := ceiling(t, o).General.Used
	second := observe(t, o, p, f, "192.0.2.11", "offset=2")
	turn(t, o)
	_, applies := blocks.calls()
	last := applies[len(applies)-1]
	if len(last) != 1 || last[0].IP != "192.0.2.11" || last[0].Victim.Action != string(victim.Attempt.ID) || last[0].Victim.IP != "192.0.2.10" {
		t.Fatalf("the engine ran %+v, want the rotated victim %s", last, victim.Attempt.ID)
	}
	if c := candidate(t, o, second); c.State != admission.StateVerified {
		t.Fatalf("the rotating block is %+v", c)
	}
	if s := ledgerStatus(t, o); s.Effects.General != 1 || ceiling(t, o).General.Used != used+1 {
		t.Fatalf("effects %+v, general used %d from %d", s.Effects, ceiling(t, o).General.Used, used)
	}
}
