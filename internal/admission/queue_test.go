package admission

import (
	"fmt"
	"math/rand/v2"
	"testing"
	"time"
)

func queueItem(key, scope string, tier Tier, eligible bool, age time.Duration) QueueItem {
	return QueueItem{Key: key, Scope: scope, Tier: tier, Eligible: eligible, Queued: t0.Add(-age)}
}

var (
	c1w = Tier{ClassC1, SeverityWarning}
	c2h = Tier{ClassC2, SeverityHigh}
	c3c = Tier{ClassC3, SeverityCritical}
)

// fill admits n items of one scope into an empty partition's free positions.
func fill(t *testing.T, v *QueueView, prefix, scope string, tier Tier, eligible bool, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		if _, ok := v.Admit(queueItem(fmt.Sprintf("%s%04d", prefix, i), scope, tier, eligible, time.Duration(n-i)*time.Second)); !ok {
			t.Fatalf("free position refused at %d", i)
		}
	}
}

func TestQueueBoundsFitThePayloadBound(t *testing.T) {
	// Spec 5.6 bounds the queue at 1000 candidates and 4 MiB of canonical
	// payload; the count must bind first, so no byte accounting is needed.
	if QueueCapacity*MaxCandidateBytes > 4<<20 || PartitionGeneral.Capacity()+PartitionReserved.Capacity() != QueueCapacity {
		t.Fatal("queue bounds disagree with the spec")
	}
}

// Free positions: an eligible item takes a reserved one first, then a
// general one; other items never take a reserved position.
func TestQueueAdmitFreePositions(t *testing.T) {
	v := NewQueueView(QueueCursors{})
	fill(t, v, "r", "host/address", c3c, true, ReservedPositions)
	if v.Count(PartitionReserved) != ReservedPositions || v.Count(PartitionGeneral) != 0 {
		t.Fatalf("eligible items took general positions early: %d/%d", v.Count(PartitionReserved), v.Count(PartitionGeneral))
	}
	p, ok := v.Admit(queueItem("extra", "host/address", c3c, true, 0))
	if !ok || p.Partition != PartitionGeneral || p.Displaced {
		t.Fatalf("eligible overflow = %+v %v", p, ok)
	}
	fill(t, v, "g", "acct:alice#1/address", c2h, false, PartitionGeneral.Capacity()-1)
	if v.Room(PartitionGeneral) || v.Len() != QueueCapacity {
		t.Fatalf("queue should be full: %d", v.Len())
	}
	for key, it := range v.items {
		if it.Partition == PartitionReserved && !it.Eligible {
			t.Fatalf("%s holds a reserved position without eligibility", key)
		}
	}
}

// A scope at its share only replaces its own lowest tier, newest entry, and
// only one that goes before the arrival: equal-tier older work stays.
func TestQueueAdmitOwnScopeOverflow(t *testing.T) {
	v := NewQueueView(QueueCursors{})
	fill(t, v, "a", "scope-a", c2h, false, PartitionGeneral.Capacity()-1)
	if _, ok := v.Admit(queueItem("low", "scope-a", c1w, false, time.Hour)); !ok {
		t.Fatal("last free position refused")
	}
	arrive := func(key string, tier Tier, seq uint64) (Placement, bool) {
		return v.Admit(QueueItem{Key: key, Scope: "scope-a", Tier: tier, Queued: t0, Seq: seq})
	}
	if _, ok := arrive("equal-low", c1w, 1); ok {
		t.Fatal("an equal-tier arrival displaced older work")
	}
	p, ok := arrive("mid", c2h, 2)
	if !ok || !p.Displaced || p.Victim.Key != "low" || v.Len() != PartitionGeneral.Capacity() {
		t.Fatalf("higher tier arrival = %+v %v", p, ok)
	}
	if _, ok = arrive("equal-mid", c2h, 3); ok {
		t.Fatal("an equal-tier arrival displaced an earlier arrival")
	}
	p, ok = arrive("high", c3c, 4)
	if !ok || p.Victim.Key != "mid" {
		t.Fatalf("next victim must be the newest of the lowest tier: %+v %v", p, ok)
	}
	p, ok = arrive("high2", c3c, 5)
	if !ok || p.Victim.Key != "a0798" {
		t.Fatalf("then the newest stored entry: %+v %v", p, ok)
	}
}

// A scope below its share reclaims one position from the scope with the
// greatest excess, taking that scope's lowest tier, newest entry even when
// it outranks the arrival.
func TestQueueAdmitNewScopeReclaims(t *testing.T) {
	v := NewQueueView(QueueCursors{})
	fill(t, v, "a", "scope-a", c3c, false, 200)
	fill(t, v, "b", "scope-b", c3c, false, 600)
	p, ok := v.Admit(QueueItem{Key: "c", Scope: "scope-c", Tier: c1w, Queued: t0, Seq: 1})
	if !ok || !p.Displaced || p.Victim.Scope != "scope-b" || p.Victim.Key != "b0599" {
		t.Fatalf("new scope reclaim = %+v %v", p, ok)
	}
	if v.Count(PartitionGeneral) != PartitionGeneral.Capacity() || v.parts[PartitionGeneral].scopes["scope-c"].count != 1 {
		t.Fatal("reclaim changed the partition size")
	}
}

// Fixed items hold positions but are never displaced.
func TestQueueAdmitNeverDisplacesFixedItems(t *testing.T) {
	v := NewQueueView(QueueCursors{})
	for i := 0; i < PartitionGeneral.Capacity(); i++ {
		it := queueItem(fmt.Sprintf("f%04d", i), "scope-a", c1w, false, time.Minute)
		it.Partition, it.Fixed = PartitionGeneral, true
		if err := v.Add(it); err != nil {
			t.Fatal(err)
		}
	}
	for _, scope := range []string{"scope-a", "scope-b"} {
		if _, ok := v.Admit(QueueItem{Key: "x-" + scope, Scope: scope, Tier: c3c, Queued: t0, Seq: 1}); ok {
			t.Fatalf("%s displaced a fixed item", scope)
		}
	}
}

// Reclaiming never takes a position from a scope at or below its share,
// even when the scope over its share has nothing displaceable.
func TestQueueAdmitNeverTakesAProtectedShare(t *testing.T) {
	v := NewQueueView(QueueCursors{})
	for i := 0; i < 700; i++ {
		it := QueueItem{Key: fmt.Sprintf("f%04d", i), Scope: "scope-a", Partition: PartitionGeneral, Tier: c1w, Queued: t0, Fixed: true}
		if err := v.Add(it); err != nil {
			t.Fatal(err)
		}
	}
	fill(t, v, "b", "scope-b", c1w, false, 100)
	if _, ok := v.Admit(QueueItem{Key: "c", Scope: "scope-c", Tier: c3c, Queued: t0, Seq: 1}); ok {
		t.Fatal("reclaim took a position from a scope below its share")
	}
	if v.Count(PartitionGeneral) != PartitionGeneral.Capacity() || v.parts[PartitionGeneral].scopes["scope-b"].count != 100 {
		t.Fatal("refused admission changed occupancy")
	}
}

// When scopes outnumber positions, a scope without a share this turn gets
// one on a later turn: the cursor rotates admission opportunities.
func TestQueueAdmitRotatesWhenScopesOutnumberPositions(t *testing.T) {
	v := NewQueueView(QueueCursors{})
	for i := 0; i < PartitionGeneral.Capacity(); i++ {
		if _, ok := v.Admit(QueueItem{Key: fmt.Sprintf("k%04d", i), Scope: fmt.Sprintf("s%04d", i), Tier: c2h, Queued: t0}); !ok {
			t.Fatal("free position refused")
		}
	}
	if _, ok := v.Admit(QueueItem{Key: "z1", Scope: "z", Tier: c2h, Queued: t0, Seq: 1}); ok {
		t.Fatal("first turn: z has no share and must wait")
	}
	if got := v.Cursors().General; got != "s0000" {
		t.Fatalf("cursor after one decision = %q", got)
	}
	p, ok := v.Admit(QueueItem{Key: "z2", Scope: "z", Tier: c2h, Queued: t0, Seq: 2})
	if !ok || p.Victim.Scope != "s0000" {
		t.Fatalf("second turn = %+v %v", p, ok)
	}
}

// Work that is already queued keeps its place in a tie: an older item that
// must be placed again wins against a newer one of the same tier.
func TestQueueAdmitTiesPreserveQueuedWork(t *testing.T) {
	v := NewQueueView(QueueCursors{})
	fill(t, v, "a", "scope-a", c2h, false, PartitionGeneral.Capacity())
	old := queueItem("old", "scope-a", c2h, false, time.Hour)
	p, ok := v.Admit(old)
	if !ok || p.Victim.Key != "a0799" {
		t.Fatalf("older equal-tier work = %+v %v", p, ok)
	}
	late := QueueItem{Key: "a", Tier: c2h, Queued: t0, Seq: 1}
	early := QueueItem{Key: "b", Tier: c2h, Queued: t0}
	if !late.newer(early) || early.newer(late) || !goesFirst(queueItem("b", "", c2h, false, 0), queueItem("a", "", c2h, false, 0)) {
		t.Fatal("ordering of equal times is not Seq then key")
	}
}

func TestQueueViewBookkeeping(t *testing.T) {
	v := NewQueueView(QueueCursors{General: "g", Reserved: "r"})
	if c := v.Cursors(); c.General != "g" || c.Reserved != "r" {
		t.Fatalf("cursors = %+v", c)
	}
	it := QueueItem{Key: "k", Scope: "s", Partition: PartitionReserved, Tier: c3c, Eligible: true, Queued: t0}
	if err := v.Add(it); err != nil {
		t.Fatal(err)
	}
	for name, bad := range map[string]QueueItem{
		"duplicate":    it,
		"no partition": {Key: "x", Scope: "s"},
		"no key":       {Scope: "s", Partition: PartitionGeneral},
		"no scope":     {Key: "y", Partition: PartitionGeneral},
	} {
		if err := v.Add(bad); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if got, ok := v.Remove("k"); !ok || got != it || v.Len() != 0 || v.Count(PartitionReserved) != 0 || len(v.parts[PartitionReserved].scopes) != 0 {
		t.Fatalf("remove = %+v %v", got, ok)
	}
	if _, ok := v.Remove("k"); ok {
		t.Fatal("removed twice")
	}
}

// Random admissions and removals keep the view consistent: counts match the
// items, the general partition never grows past its capacity from below,
// reserved positions hold only eligible items, and fixed items stay.
func TestQueueViewRandomInvariants(t *testing.T) {
	r := rand.New(rand.NewPCG(1, 2))
	v := NewQueueView(QueueCursors{})
	fixed := map[string]bool{}
	tiers := []Tier{c1w, c2h, c3c}
	for step := 0; step < 20000; step++ {
		key := fmt.Sprintf("i%05d", step)
		scope := fmt.Sprintf("s%d", r.IntN(12))
		switch op := r.IntN(10); {
		case op < 7:
			x := QueueItem{Key: key, Scope: scope, Tier: tiers[r.IntN(3)], Eligible: r.IntN(3) == 0, Queued: t0.Add(time.Duration(step) * time.Millisecond), Seq: uint64(step + 1)}
			p, ok := v.Admit(x)
			if ok && p.Displaced && fixed[p.Victim.Key] {
				t.Fatalf("step %d displaced a fixed item", step)
			}
		case op < 8 && v.Room(PartitionGeneral):
			it := QueueItem{Key: key, Scope: scope, Partition: PartitionGeneral, Queued: t0, Fixed: true}
			if err := v.Add(it); err != nil {
				t.Fatal(err)
			}
			fixed[key] = true
		default:
			for k := range v.items {
				v.Remove(k)
				delete(fixed, k)
				break
			}
		}
		total := 0
		for p := PartitionGeneral; p < partitionEnd; p++ {
			n := 0
			for _, sq := range v.parts[p].scopes {
				if sq.count == 0 || len(sq.victims) > sq.count {
					t.Fatalf("step %d: scope bookkeeping broken", step)
				}
				n += sq.count
			}
			if n != v.parts[p].count || n > p.Capacity() {
				t.Fatalf("step %d: partition %s holds %d, counted %d", step, p, n, v.parts[p].count)
			}
			total += n
		}
		if total != v.Len() {
			t.Fatalf("step %d: %d items, %d positions", step, v.Len(), total)
		}
		for k := range fixed {
			if _, ok := v.items[k]; !ok {
				t.Fatalf("step %d: fixed item %s vanished", step, k)
			}
		}
		for _, it := range v.items {
			if it.Partition == PartitionReserved && !it.Eligible {
				t.Fatalf("step %d: ineligible item in a reserved position", step)
			}
		}
	}
}

func TestQueueTransferAllocation(t *testing.T) {
	v := NewDurableQueueView(QueueCursors{})
	total := 0
	for p := PartitionGeneral; p < partitionEnd; p++ {
		if p.DurableCapacity()+IngressPositions != p.Capacity() || IngressPositions < 1 {
			t.Fatal("transfer allocation is outside the partition")
		}
		for i := 0; i < p.DurableCapacity(); i++ {
			it := QueueItem{Key: fmt.Sprintf("%d-%d", p, i), Scope: "host/address", Partition: p, Tier: c2h, Eligible: p == PartitionReserved, Queued: t0}
			if err := v.Add(it); err != nil {
				t.Fatal(err)
			}
		}
		if v.Room(p) {
			t.Fatal("durable work borrowed transfer space")
		}
		total += v.Count(p) + IngressPositions
	}
	if total != QueueCapacity {
		t.Fatalf("combined positions = %d", total)
	}
	if _, ok := v.Admit(QueueItem{Key: "arrival", Scope: "host/address", Tier: c2h, Queued: t0.Add(time.Second)}); ok {
		t.Fatal("equal-tier arrival consumed transfer space")
	}
}
