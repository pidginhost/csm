package learn

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/store"
)

type failOperatorOutcomeKV struct {
	kv
	id   string
	fail bool
}

func (f *failOperatorOutcomeKV) LearnUpdate(fn func(store.LearnTx) error) error {
	return f.kv.LearnUpdate(func(tx store.LearnTx) error {
		if err := fn(tx); err != nil {
			return err
		}
		op, _, err := (LedgerView{tx: tx}).Op(f.id)
		if err != nil {
			return err
		}
		if f.fail && op.Outcome != nil && op.Outcome.Outcome != "" {
			return errors.New("outcome commit failed")
		}
		return nil
	})
}

func TestOperatorRetryRetainsDigestsAfterOutcomeWriteFailure(t *testing.T) {
	for _, action := range []string{ActionSpam, ActionForget} {
		t.Run(action, func(t *testing.T) {
			f := newAuditFixture(t)
			f.add(t, 1, digest('a'), 2, t0, 2002)
			id := "0123456789abcdef0123456789abcdef"
			faults := &failOperatorOutcomeKV{kv: f.ledger.db, id: id, fail: true}
			f.ledger.db = faults
			e := newTestEngine(t, f)
			snapshot := f.report("operator message", digest('a'), digest('a'), 1)
			f.storage.onAdd = func(Digest, int32) (bool, error) { return false, ErrUncertain }
			f.storage.onDelete = func(Digest) (bool, error) { return false, ErrUncertain }
			req := OperatorRequest{Action: action, RequestID: id, Snapshot: snapshot, SnapshotSHA: sha(snapshot)}
			res, err := e.Operator(context.Background(), req)
			if !errors.Is(err, ErrStateIO) || !slices.Equal(res.Digests, []Digest{digest('a')}) {
				t.Fatalf("first result %+v, error %v", res, err)
			}
			faults.fail = false
			f.storage.onAdd, f.storage.onDelete = nil, nil
			// The failed attempt reserved nothing: its outcome commits with
			// the reservation. A retry that cannot inspect the file fails,
			// yet still reports the digests recorded on the first attempt.
			inspect := f.storage.inspect[string(snapshot)]
			f.storage.mu.Lock()
			delete(f.storage.inspect, string(snapshot))
			f.storage.mu.Unlock()
			res, err = e.Operator(context.Background(), req)
			if err == nil || !slices.Equal(res.Digests, []Digest{digest('a')}) {
				t.Fatalf("uninspectable retry result %+v, error %v", res, err)
			}
			f.storage.mu.Lock()
			f.storage.inspect[string(snapshot)] = inspect
			f.storage.mu.Unlock()
			res, err = e.Operator(context.Background(), req)
			if err != nil || !res.ExitOK || !slices.Equal(res.Digests, []Digest{digest('a')}) {
				t.Fatalf("retry result %+v, error %v", res, err)
			}
		})
	}
}

func TestOperatorAssignmentFailureRetainsDigests(t *testing.T) {
	f := newAuditFixture(t)
	f.add(t, 1, digest('a'), 2, t0, 2002)
	e := newTestEngine(t, f)
	if err := f.ledger.Update(func(tx LedgerTx) error {
		return tx.tx.Put(store.LearnUsageBucket, []byte("operator"), []byte("{"))
	}); err != nil {
		t.Fatal(err)
	}
	snapshot := f.report("operator message", digest('a'), digest('a'), 1)
	req := OperatorRequest{Action: ActionSpam, RequestID: "0123456789abcdef0123456789abcdef", Snapshot: snapshot, SnapshotSHA: sha(snapshot)}
	res, err := e.Operator(context.Background(), req)
	if !errors.Is(err, ErrStateIO) || !slices.Equal(res.Digests, []Digest{digest('a')}) {
		t.Fatalf("result %+v, error %v", res, err)
	}
	if _, _, adds, deletes := f.storage.native(); adds != 0 || deletes != 0 {
		t.Fatal("assignment failure mutated storage")
	}
}

// The outcome commits in the same transaction as the reservation and the
// mark, so a failed outcome write leaves nothing published, and the retry
// adds exactly one mark.
func TestOperatorDuplicateAfterOutcomeWriteFailureSucceeds(t *testing.T) {
	f := newAuditFixture(t)
	f.add(t, 1, digest('a'), 2, t0, 2002)
	id := "0123456789abcdef0123456789abcdef"
	faults := &failOperatorOutcomeKV{kv: f.ledger.db, id: id, fail: true}
	f.ledger.db = faults
	e := newTestEngine(t, f)
	snapshot := f.report("operator message", digest('a'), digest('a'), 1)
	req := OperatorRequest{Action: ActionSpam, RequestID: id, Snapshot: snapshot, SnapshotSHA: sha(snapshot)}
	if _, err := e.Operator(context.Background(), req); !errors.Is(err, ErrStateIO) {
		t.Fatalf("outcome write error %v", err)
	}
	if _, _, adds, _ := f.storage.native(); adds != 0 {
		t.Fatalf("a failed reservation published %d adds", adds)
	}
	faults.fail = false
	res, err := e.Operator(context.Background(), req)
	if err != nil || !res.ExitOK || res.Outcome != ResultCommitted || len(res.Clusters) != 1 || res.Clusters[0].Result != ResultCommitted {
		t.Fatalf("retry result %+v, error %v", res, err)
	}
	again, err := e.Operator(context.Background(), req)
	if err != nil || again.Outcome != ResultCommitted {
		t.Fatalf("recorded result %+v, error %v", again, err)
	}
	if _, _, adds, _ := f.storage.native(); adds != 1 {
		t.Fatalf("retries published %d marks", adds)
	}
}

func TestOperatorCancellationDoesNotRaceWithCompletion(t *testing.T) {
	f := newAuditFixture(t)
	f.add(t, 1, digest('a'), 2, t0, 2002)
	e := newTestEngine(t, f)
	snapshot := f.report("operator message", digest('a'), digest('a'), 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	f.storage.onInspect = func() {
		cancel()
		// Keep native work in flight after the caller has stopped waiting.
		time.Sleep(10 * time.Millisecond)
	}
	req := OperatorRequest{Action: ActionSpam, RequestID: "0123456789abcdef0123456789abcdef", Snapshot: snapshot, SnapshotSHA: sha(snapshot)}
	res, err := e.Operator(ctx, req)
	if !errors.Is(err, context.Canceled) || res.RequestID != req.RequestID || res.ExitOK {
		t.Fatalf("cancelled result %+v, error %v", res, err)
	}
	time.Sleep(30 * time.Millisecond)
	res, err = e.Operator(context.Background(), req)
	if err != nil || !res.ExitOK || len(res.Digests) != 1 {
		t.Fatalf("settled result %+v, error %v", res, err)
	}
}
