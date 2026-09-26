package admission

import (
	"fmt"
	"testing"
	"time"
)

// Submit against a snapshot whose durable general positions are all held,
// each by its own scope: the widest fair-share computation per call. It
// measures and does not gate.
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
	in.Publish(&QueueSnapshot{Now: t0, Inventory: testInventory(b), Items: items, Revision: 1, Generation: 1})
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		target, err := CanonicalAddress(fmt.Sprintf("2001:db8::%x", i+1), Caps{IPv6: true})
		if err != nil {
			b.Fatal(err)
		}
		e, err := tp.ssh.Mint(EvidenceInput{
			Check: "ssh_brute", FindingID: "0123456789abcdef", Severity: SeverityHigh, Target: target,
			Observation: ObservationRef{Stream: "bench", Cursor: fmt.Sprintf("c%d", i), Version: 1},
			ObservedAt:  t0, Parser: ParserRef{Name: "bench", Version: 1},
		})
		if err != nil {
			b.Fatal(err)
		}
		b.StartTimer()
		_ = in.Submit(Submission{Kind: KindBlockIP, Target: target, Evidence: e})
	}
}
