package learn

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/store"
)

func numDigest(i int) Digest { return Digest(fmt.Sprintf("%0128x", i)) }

// ledgerBytes sums logical learning keys and values. bbolt pages add
// their fill overhead.
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

// putClusters writes live clusters with one contribution per alias, or
// retired zero-target guards. Bodies are unnecessary for exact audits.
func putClusters(b testing.TB, f *auditFixture, from, n, aliases int, tv int32) {
	b.Helper()
	bodySHA := sha([]byte(strings.Repeat("x", 4096)))
	for start := from; start < from+n; start += 1000 {
		end := min(start+1000, from+n)
		if err := f.ledger.Update(func(tx LedgerTx) error {
			for i := start; i < end; i++ {
				id := uint64(i + 1) // #nosec G115 -- benchmark counter
				d := numDigest(i * 64)
				if tv == 0 {
					guard := Charge{UID: 2000 + i%100, Usage: Usage{Aliases: 1}}
					if err := tx.AddUsage(guard.UID, false, guard.Usage); err != nil {
						return err
					}
					if err := tx.PutTarget(Target{Digest: d, ClusterID: id, Revision: 3, Phase: PhaseIdle, Updated: t0, GuardCharge: &guard}); err != nil {
						return err
					}
					continue
				}
				c := Cluster{ID: id, Anchor: d, BodyLen: 4096, BodySHA: bodySHA, Revision: uint64(aliases + 1), Created: t0, LastReport: t0} // #nosec G115 -- benchmark counter
				for a := range aliases {
					uid := 2000 + i%100 + a*100
					charge := Usage{Aliases: 1}
					if a == 0 {
						charge.BodyBytes = c.BodyLen
					}
					c.UIDs = append(c.UIDs, uid)
					c.Charges = append(c.Charges, Charge{UID: uid, Usage: charge})
					if err := tx.AddUsage(uid, false, charge); err != nil {
						return err
					}
					alias := numDigest(i*64 + a)
					c.Aliases = append(c.Aliases, alias)
					if err := tx.PutAlias(alias, id); err != nil {
						return err
					}
				}
				if err := tx.PutCluster(c); err != nil {
					return err
				}
				if err := tx.PutTarget(Target{Digest: d, ClusterID: id, T: tv, Revision: uint64(aliases), Phase: PhaseIdle, Updated: t0}); err != nil { // #nosec G115 -- benchmark counter
					return err
				}
				f.storage.values[d] = int64(tv)
			}
			return nil
		}); err != nil {
			b.Fatal(err)
		}
	}
}

func TestBenchmarkClusterAccounting(t *testing.T) {
	f := newAuditFixture(t)
	putClusters(t, f, 0, 1, 8, 8*UIDWeight)
	c, ok := f.cluster(t, 1)
	if !ok || len(c.BodySHA) != 64 || len(c.UIDs) != 8 || len(c.Charges) != 8 || len(c.Aliases) != 8 {
		t.Fatalf("incomplete cluster: %+v", c)
	}
	if err := f.ledger.View(func(v LedgerView) error {
		for i, ch := range c.Charges {
			want := Usage{Aliases: 1}
			if i == 0 {
				want.BodyBytes = c.BodyLen
			}
			usage, err := v.Usage(c.UIDs[i], false)
			if err != nil || ch.UID != c.UIDs[i] || ch.Usage != want || usage != want {
				t.Errorf("contributor %d: charge %+v, usage %+v, want %+v, err %v", i, ch, usage, want, err)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestBenchmarkZeroTargetAccounting(t *testing.T) {
	f := newAuditFixture(t)
	putClusters(t, f, 0, 1, 1, 0)
	if err := f.ledger.View(func(v LedgerView) error {
		if _, ok, err := v.Cluster(1); err != nil || ok {
			t.Fatalf("retired cluster remains: present %v, err %v", ok, err)
		}
		if _, ok, err := v.Alias(numDigest(0)); err != nil || ok {
			t.Fatalf("retired alias remains: present %v, err %v", ok, err)
		}
		target, ok, err := v.Target(numDigest(0))
		want := Charge{UID: 2000, Usage: Usage{Aliases: 1}}
		if err != nil || !ok || target.T != 0 || target.Phase != PhaseIdle || target.GuardCharge == nil || *target.GuardCharge != want {
			t.Fatalf("zero target: %+v, present %v, err %v", target, ok, err)
		}
		usage, err := v.Usage(want.UID, false)
		if err != nil || usage != want.Usage {
			t.Fatalf("guard usage: %+v, err %v", usage, err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// BenchmarkClusterBytes measures logical ledger growth for a fixed mix of
// clusters and contributors, including their persisted usage and charges.
func BenchmarkClusterBytes(b *testing.B) {
	const n, aliases = 2000, 8
	f := newAuditFixture(b)
	b.ResetTimer()
	for range b.N {
		b.StopTimer()
		if err := f.ledger.db.(*store.DB).ResetLearning(); err != nil {
			b.Fatal(err)
		}
		if err := f.ledger.Bind("gen1", "prefix1"); err != nil {
			b.Fatal(err)
		}
		before := ledgerBytes(b, f)
		b.StartTimer()
		putClusters(b, f, 0, n, aliases, aliases*UIDWeight)
		b.StopTimer()
		b.ReportMetric(float64(ledgerBytes(b, f)-before)/n, "bytes/cluster")
	}
}

// BenchmarkPublishTurn admits one report that joins a live cluster and
// publishes its new target through the fake client: the CSM-side cost of
// one contribution, ledger writes and fsyncs included.
func BenchmarkPublishTurn(b *testing.B) {
	f := newAuditFixture(b)
	b.ResetTimer()
	for range b.N {
		b.StopTimer()
		if err := f.ledger.db.(*store.DB).ResetLearning(); err != nil {
			b.Fatal(err)
		}
		if err := f.ledger.Bind("gen1", "prefix1"); err != nil {
			b.Fatal(err)
		}
		f.storage = newStorage()
		f.add(b, 1, digest('a'), UIDWeight, t0, 2002)
		e, stop := startTestEngine(b, f)
		snapshot := f.report("report", digest('b'), digest('a'), 0.9)
		b.StartTimer()
		out, err := e.Submit(context.Background(), Candidate{UID: 3000, Snapshot: snapshot})
		b.StopTimer()
		stop()
		if err != nil || out.Err != nil || out.Deferred || !slices.Equal(out.Committed, []uint64{1}) || len(out.Pending)+len(out.Skips)+len(out.Duplicates) != 0 {
			b.Fatalf("submit: %+v, %v", out, err)
		}
		if err := f.ledger.View(func(v LedgerView) error {
			c, _, err := v.Cluster(1)
			if err == nil && (len(c.UIDs) != 2 || len(c.Aliases) != 2) {
				b.Fatalf("publication workload grew: %d contributors, %d aliases", len(c.UIDs), len(c.Aliases))
			}
			return err
		}); err != nil {
			b.Fatal(err)
		}
		if value, ok := f.storage.value(digest('a')); !ok || value != 2*UIDWeight {
			b.Fatalf("published value: %d, present: %v", value, ok)
		}
		if err := f.bodies.Remove(1); err != nil {
			b.Fatal(err)
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
		turns, checked := 0, 0
		for {
			prog, err := p.AuditTurn(context.Background(), AuditBatch, t0)
			if err != nil {
				b.Fatal(err)
			}
			turns++
			checked += prog.Checked
			if prog.Repaired != 0 {
				b.Fatalf("clean audit scheduled %d repairs", prog.Repaired)
			}
			if prog.RotationDone {
				break
			}
			if turns >= (20000+AuditBatch-1)/AuditBatch {
				b.Fatal("audit did not finish a rotation")
			}
		}
		if checked != 20000 || !p.FreshMatchingAllowed() {
			b.Fatalf("incomplete audit coverage: checked %d, matching allowed %v", checked, p.FreshMatchingAllowed())
		}
		b.ReportMetric(float64(turns), "turns/rotation")
	}
}
