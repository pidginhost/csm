package learn

import "testing"

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
	if !s.AuditCompleted.Equal(t0) || s.Reconstructed == 0 {
		t.Fatalf("audit stats %+v", s)
	}
}
