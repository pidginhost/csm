package learn

import (
	"reflect"
	"testing"
)

// Spec 8: root-only status exposes pending request IDs and per-cluster
// phases, so a lost CLI reply can be looked up.
func TestRequestStatusReportsPhases(t *testing.T) {
	f := newAuditFixture(t)
	f.add(t, 1, digest('a'), 2, t0, 2002)
	pendingID, doneID := "0123456789abcdef0123456789abcdef", "fedcba9876543210fedcba9876543210"
	if err := f.ledger.Update(func(tx LedgerTx) error {
		if err := tx.PutOp(OpRecord{RequestID: pendingID, Action: ActionSpam, SnapshotSHA: "s1",
			Outcome: &OpOutcome{Clusters: []ClusterOutcome{{ClusterID: 1, Result: ResultPending}}, Outcome: ResultPending, Digests: []Digest{digest('a')}}}); err != nil {
			return err
		}
		if err := tx.PutIntent(Intent{ID: pendingID, Kind: IntentOperator, MarkID: pendingID, Clusters: []IntentCluster{{ClusterID: 1, Anchor: digest('a'), Revision: 2, NewT: 20}}}); err != nil {
			return err
		}
		if err := tx.PutTarget(Target{Digest: digest('a'), ClusterID: 1, T: 20, Revision: 2, Phase: PhaseAddSent}); err != nil {
			return err
		}
		return tx.PutOp(OpRecord{RequestID: doneID, Action: ActionForget, SnapshotSHA: "s2", Done: true,
			Outcome: &OpOutcome{Clusters: []ClusterOutcome{{ClusterID: 3, Result: ResultForgotten}}, Outcome: ResultForgotten, ExitOK: true}})
	}); err != nil {
		t.Fatal(err)
	}
	got, err := RequestStatus(f.ledger, []string{pendingID, doneID, "00000000000000000000000000000000"})
	if err != nil {
		t.Fatal(err)
	}
	want := []Status{
		{RequestID: pendingID, Action: ActionSpam, Found: true, Outcome: ResultPending, Digests: []Digest{digest('a')},
			Clusters: []StatusCluster{{ClusterID: 1, Result: ResultPending, Phase: PhaseAddSent}}},
		{RequestID: doneID, Action: ActionForget, Found: true, Done: true, ExitOK: true, Outcome: ResultForgotten,
			Clusters: []StatusCluster{{ClusterID: 3, Result: ResultForgotten}}},
		{RequestID: "00000000000000000000000000000000"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("status\n got %+v\nwant %+v", got, want)
	}
	all, err := RequestStatus(f.ledger, nil)
	if err != nil || len(all) != 1 || all[0].RequestID != pendingID {
		t.Fatalf("pending list %+v err %v", all, err)
	}
}
