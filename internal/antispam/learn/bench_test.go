package learn

import (
	"context"
	"fmt"
	"testing"

	"github.com/pidginhost/csm/internal/store"
)

func numDigest(i int) Digest { return Digest(fmt.Sprintf("%0128x", i)) }

// ledgerBytes sums the learning records' keys and values: the logical
// state the allowances bound. bbolt pages add their fill overhead.
func ledgerBytes(b *testing.B, f *auditFixture) int64 {
	b.Helper()
	var size int64
	if err := f.ledger.View(func(v LedgerView) error {
		for _, name := range store.LearnBuckets {
			if err := v.tx.ForEach(name, func(k, val []byte) error {
				size += int64(len(k) + len(val))
				return nil
			}); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		b.Fatal(err)
	}
	return size
}

// putClusters writes n clusters of aliases aliases each, with live targets
// at tv, straight into the ledger; storage holds their values.
func putClusters(b *testing.B, f *auditFixture, from, n, aliases int, tv int32) {
	b.Helper()
	for start := from; start < from+n; start += 1000 {
		end := min(start+1000, from+n)
		if err := f.ledger.Update(func(tx LedgerTx) error {
			for i := start; i < end; i++ {
				id := uint64(i + 1) // #nosec G115 -- benchmark counter
				d := numDigest(i * 64)
				c := Cluster{ID: id, Anchor: d, BodyLen: 4096, UIDs: []int{2000 + i%100}, Revision: 1, Created: t0, LastReport: t0}
				for a := range aliases {
					alias := numDigest(i*64 + a)
					c.Aliases = append(c.Aliases, alias)
					if err := tx.PutAlias(alias, id); err != nil {
						return err
					}
				}
				if err := tx.PutCluster(c); err != nil {
					return err
				}
				if err := tx.PutTarget(Target{Digest: d, ClusterID: id, T: tv, Revision: 1, Phase: PhaseIdle}); err != nil {
					return err
				}
				if tv > 0 {
					f.storage.values[d] = int64(tv)
				}
			}
			return nil
		}); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkClusterBytes measures ledger growth per cluster with 8 aliases,
// the per-account allowance's unit of state.
func BenchmarkClusterBytes(b *testing.B) {
	const n, aliases = 2000, 8
	for range b.N {
		f := newAuditFixture(b)
		before := ledgerBytes(b, f)
		putClusters(b, f, 0, n, aliases, 2)
		b.ReportMetric(float64(ledgerBytes(b, f)-before)/n, "bytes/cluster")
	}
}

// BenchmarkPublishTurn admits one report that joins a live cluster and
// publishes its new target through the fake client: the CSM-side cost of
// one contribution, ledger writes and fsyncs included.
func BenchmarkPublishTurn(b *testing.B) {
	f := newAuditFixture(b)
	f.add(b, 1, digest('a'), 2, t0, 2002)
	e := newTestEngine(b, f)
	snapshots := make([][]byte, b.N)
	for i := range snapshots {
		snapshots[i] = f.report(fmt.Sprintf("report %d", i), numDigest(1000000+i), digest('a'), 0.9)
	}
	b.ResetTimer()
	for i := range b.N {
		out, err := e.Submit(context.Background(), Candidate{UID: 3000 + i, Snapshot: snapshots[i]})
		if err != nil || out.Deferred {
			b.Fatalf("submit %d: %+v, %v", i, out, err)
		}
	}
}

// BenchmarkAuditRotation runs one full audit rotation over 10000 live and
// 10000 zero targets with the fake client.
func BenchmarkAuditRotation(b *testing.B) {
	f := newAuditFixture(b)
	putClusters(b, f, 0, 10000, 1, 2)
	putClusters(b, f, 10000, 10000, 1, 0)
	b.ResetTimer()
	for range b.N {
		p := f.publisher()
		turns := 0
		for {
			prog, err := p.AuditTurn(context.Background(), AuditBatch, t0)
			if err != nil {
				b.Fatal(err)
			}
			turns++
			if prog.RotationDone && turns > 1 {
				break
			}
		}
		b.ReportMetric(float64(turns), "turns/rotation")
	}
}
