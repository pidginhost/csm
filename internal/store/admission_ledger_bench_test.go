package store

import (
	"fmt"
	"net/netip"
	"testing"

	"github.com/pidginhost/csm/internal/admission"
	bolt "go.etcd.io/bbolt"
)

// These benchmarks measure the queue at its worst: every durable general
// position held and every candidate carrying the maximum number of roots.
// Each call below scans the whole live queue. They measure and do not gate.

// fillRoots queues n candidates in one transaction, each from roots fresh
// observations of its own documentation address.
func (f *ledgerFixture) fillRoots(n, roots int) {
	f.t.Helper()
	f.l.mu.Lock()
	defer f.l.mu.Unlock()
	if err := f.l.update("fill", func(tx *bolt.Tx) error {
		q, err := f.l.openQueue(tx, f.l.now)
		if err != nil {
			return err
		}
		for i := 0; i < n; i++ {
			f.fills++
			target := fmt.Sprintf("2001:db8::%x", f.fills)
			var ids []admission.EvidenceID
			for r := 0; r < roots; r++ {
				e := f.mint(evidenceSpec{target: target, cursor: fmt.Sprintf("fill=%d/%d", f.fills, r)})
				data, err := e.MarshalBinary()
				if err != nil {
					return err
				}
				if err = tx.Bucket([]byte(admissionEvidenceBucket)).Put([]byte(e.ID()), data); err != nil {
					return err
				}
				ids = append(ids, e.ID())
			}
			req := f.request(target, ids[0], ids[1:]...)
			key := admission.CandidateKey{Kind: req.Kind, Target: req.Target, Episode: req.Episode, Generation: req.Generation}
			id, err := key.ID()
			if err != nil {
				return err
			}
			all, err := rootSet(req)
			if err != nil {
				return err
			}
			if _, _, err = f.l.enqueueTx(q, req, key, id, all); err != nil {
				return err
			}
		}
		return q.flush()
	}); err != nil {
		f.t.Fatal(err)
	}
}

func fullLedger(b *testing.B) *ledgerFixture {
	b.Helper()
	f := newLedgerFixture(b)
	f.fillRoots(admission.PartitionGeneral.DurableCapacity(), admission.MaxRoots)
	if n := f.candidateCount(); n != admission.PartitionGeneral.DurableCapacity() {
		b.Fatalf("queued %d candidates", n)
	}
	return f
}

func BenchmarkAdmissionLedgerScheduleFullQueue(b *testing.B) {
	f := fullLedger(b)
	lim := admission.ScheduleLimits{General: admission.MaxBatchMembers, Members: admission.MaxBatchMembers}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if picks, err := f.l.Schedule(lim); err != nil || len(picks) != admission.MaxBatchMembers {
			b.Fatalf("schedule: %d picks, %v", len(picks), err)
		}
	}
}

func BenchmarkAdmissionLedgerRevalidateFullQueue(b *testing.B) {
	f := fullLedger(b)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := f.l.Revalidate(); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkAdmissionLedgerRefreshInventoryFullQueue(b *testing.B) {
	f := fullLedger(b)
	obs := admission.InventoryObservation{Accounts: []string{"alice", "bob"}}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := f.l.RefreshInventory(obs); err != nil {
			b.Fatal(err)
		}
	}
}

// A full group of arrivals against the full queue: each one is refused for
// overflow, the costliest path through admission.
func BenchmarkAdmissionLedgerEnqueueGroupFullQueue(b *testing.B) {
	f := fullLedger(b)
	f.begin()
	next := netip.MustParseAddr("2001:db8:1::1")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		group := make([]admission.Arrival, admission.MaxArrivalGroup)
		for j := range group {
			f.fills++
			group[j] = f.arrival(evidenceSpec{target: next.String(), cursor: fmt.Sprintf("group=%d", f.fills)})
			next = next.Next()
		}
		b.StartTimer()
		results, _, err := f.l.EnqueueGroup(group, nil)
		if err != nil || len(results) != len(group) {
			b.Fatalf("group: %d results, %v", len(results), err)
		}
	}
}
