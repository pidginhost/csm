package learn

import (
	"context"
	"sync/atomic"
	"testing"
)

func TestEngineStats(t *testing.T) {
	f := newAuditFixture(t)
	f.add(t, 1, digest('a'), 2, t0, 2002)
	f.add(t, 2, digest('b'), 0, t0, 2003)
	f.add(t, 3, digest('c'), 4, t0, 2004)
	// The audit at start finds anchor c missing and reconstructs it.
	delete(f.storage.values, digest('c'))
	var bodyBytes int64
	for _, id := range []uint64{1, 2, 3} {
		c, _ := f.cluster(t, id)
		bodyBytes += c.BodyLen
	}
	e := newTestEngine(t, f)
	// A send with an unknown outcome, recorded after the start-up audit.
	if err := f.ledger.Update(func(tx LedgerTx) error {
		return tx.PutTarget(Target{Digest: digest('d'), ClusterID: 1, T: 2, Revision: 1, Phase: PhaseAddSent})
	}); err != nil {
		t.Fatal(err)
	}
	s, err := e.Stats()
	if err != nil {
		t.Fatal(err)
	}
	if s.LiveClusters != 3 || s.ZeroTargets != 1 || s.UncertainIntents != 1 || s.BodyBytes != bodyBytes {
		t.Fatalf("stats %+v, want body bytes %d", s, bodyBytes)
	}
	if !s.AuditCompleted.Equal(t0) || s.Reconstructed != 1 {
		t.Fatalf("audit stats %+v", s)
	}
}

func TestReportCommitNotificationIncludesBackgroundRetry(t *testing.T) {
	f := newAuditFixture(t)
	e := newTestEngine(t, f)
	var commits atomic.Int64
	if err := e.do(context.Background(), func() {
		e.cfg.OnReportCommit = func() { commits.Add(1) }
	}); err != nil {
		t.Fatal(err)
	}
	snap := []byte("synthetic spam")
	f.storage.bodies[string(snap)] = digest('s')
	f.storage.onAdd = func(Digest, int32) (bool, error) { return true, ErrUncertain }
	out, err := e.Submit(context.Background(), Candidate{UID: 1001, Snapshot: snap})
	if err != nil || len(out.Pending) != 1 || len(out.Committed) != 0 || commits.Load() != 0 {
		t.Fatalf("pending outcome %+v, error %v, commits %d", out, err, commits.Load())
	}
	f.storage.onAdd = nil
	for range 2 {
		if err = e.do(context.Background(), func() { e.background(context.Background()) }); err != nil {
			t.Fatal(err)
		}
	}
	if got := commits.Load(); got != 1 {
		t.Fatalf("background commits = %d, want 1", got)
	}
	out, err = e.Submit(context.Background(), Candidate{UID: 1002, Snapshot: snap})
	if err != nil || len(out.Committed) != 1 || commits.Load() != 2 {
		t.Fatalf("immediate outcome %+v, error %v, commits %d", out, err, commits.Load())
	}
	out, err = e.Submit(context.Background(), Candidate{UID: 1002, Snapshot: snap})
	if err != nil || len(out.Duplicates) != 1 || commits.Load() != 2 {
		t.Fatalf("duplicate outcome %+v, error %v, commits %d", out, err, commits.Load())
	}
	op, err := e.Operator(context.Background(), opRequest(ActionSpam, snap))
	if err != nil || op.Outcome != ResultCommitted || commits.Load() != 2 {
		t.Fatalf("operator outcome %+v, error %v, report commits %d", op, err, commits.Load())
	}
}
