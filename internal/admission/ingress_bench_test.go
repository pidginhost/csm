package admission

import (
	"fmt"
	"testing"
	"time"
)

// Both general allocations start full, each position in its own scope, so
// every measured call computes fair shares. Timing measures and does not gate.
func BenchmarkIngressSubmitFullSnapshot(b *testing.B) {
	tp := newTestProducers(b)
	tp.reg.Seal()
	in, err := NewIngress(tp.reg)
	if err != nil {
		b.Fatal(err)
	}
	items := make([]QueueItem, PartitionGeneral.DurableCapacity())
	for i := range items {
		items[i] = QueueItem{Key: fmt.Sprintf("cand_%032x", i+1), Scope: fmt.Sprintf("acct:s%d#%d/address", i, i+1), Partition: PartitionGeneral,
			Tier: Tier{ClassC2, SeverityHigh}, Queued: t0.Add(-time.Duration(len(items)-i) * time.Second)}
	}
	accounts := make(map[string]uint64, PartitionGeneral.Capacity())
	for i := range items {
		accounts[fmt.Sprintf("s%d", i)] = uint64(i + 1)
	}
	for i := 0; i < IngressPositions; i++ {
		accounts[fmt.Sprintf("held%d", i)] = uint64(i + 1)
	}
	inv, err := NewInventory(accounts, nil)
	if err != nil {
		b.Fatal(err)
	}
	in.Publish(&QueueSnapshot{Now: t0, Inventory: inv, Items: items, Revision: 1, Generation: 1})
	target, err := CanonicalAddress("2001:db8::1", Caps{IPv6: true})
	if err != nil {
		b.Fatal(err)
	}
	submission := func(cursor string, owner Owner) Submission {
		e, mintErr := tp.ssh.Mint(EvidenceInput{
			Check: "ssh_brute", FindingID: "0123456789abcdef", Severity: SeverityHigh, Target: target, Owner: owner,
			Observation: ObservationRef{Stream: "bench", Cursor: cursor, Version: 1},
			ObservedAt:  t0, Parser: ParserRef{Name: "bench", Version: 1},
		})
		if mintErr != nil {
			b.Fatal(mintErr)
		}
		return Submission{Kind: KindBlockIP, Target: target, Evidence: e}
	}
	for i := 0; i < IngressPositions; i++ {
		name := fmt.Sprintf("held%d", i)
		if err = in.Submit(submission(name, inv.Resolve(Claim{ClaimAccount, name}))); err != nil {
			b.Fatal(err)
		}
	}
	if in.view.Count(PartitionGeneral) != PartitionGeneral.Capacity() {
		b.Fatal("benchmark must start with full durable and ingress allocations")
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		sub := submission(fmt.Sprintf("c%d", i), HostOwner())
		b.StartTimer()
		_ = in.Submit(sub)
	}
}
