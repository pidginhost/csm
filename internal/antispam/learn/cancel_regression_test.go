package learn

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"testing"

	"github.com/pidginhost/csm/internal/store"
)

// A sent reservation cannot be cancelled. Checking it must not wait for
// the owner, which may be blocked on unrelated native requests.
func TestCancelUnsentSentOnlySkipsOwner(t *testing.T) {
	for _, deletion := range []bool{false, true} {
		t.Run(map[bool]string{false: "add", true: "delete"}[deletion], func(t *testing.T) {
			f := newAuditFixture(t)
			f.add(t, 1, digest('a'), 2, t0, 2002)
			e, stop := startTestEngine(t, f)
			t.Cleanup(stop)
			f.storage.mu.Lock()
			f.storage.syncErr = errors.New("flush reply lost")
			f.storage.mu.Unlock()
			if deletion {
				f.storage.set(digest('a'), 8)
			}
			out, err := e.SubmitReport(context.Background(), Candidate{UID: 1001, Snapshot: f.report("variant", digest('v'), digest('a'), 1)})
			if err != nil || !slices.Equal(out.Pending, []uint64{1}) {
				t.Fatalf("pending reservation: %+v, %v", out, err)
			}
			before, _ := f.targetOf(t, digest('a'))
			wantPhase := PhaseAddSent
			if deletion {
				wantPhase = PhaseDeleteSent
			}
			if before.Phase != wantPhase || before.SentRevision != before.Revision {
				t.Fatalf("write was not journaled: %+v", before)
			}
			stop()
			if err := e.CancelUnsent(context.Background(), 1001); err != nil {
				t.Fatal(err)
			}
			if after, _ := f.targetOf(t, digest('a')); !reflect.DeepEqual(after, before) || f.intents(t) != 1 {
				t.Fatalf("sent reservation changed: %+v", after)
			}
		})
	}
}

// A rejected delete is still a journaled native write, even though the
// publisher has moved back to DeletePending. Other parts remain unsent.
func TestCancelUnsentMixedDeleteAndReadFailure(t *testing.T) {
	f := newAuditFixture(t)
	f.add(t, 1, digest('a'), 2, t0, 2002)
	f.add(t, 2, digest('b'), 2, t0, 2003)
	e := newTestEngine(t, f)
	f.storage.set(digest('a'), 8)
	f.storage.mu.Lock()
	f.storage.onDelete = func(Digest) (bool, error) { return false, ErrRejected }
	f.storage.inspect["multipart"] = []Result{
		{Queried: digest('v'), Stored: digest('a'), Found: true, Confirmed: true, Prob: 1, Value: 2, Flag: 1},
		{Queried: digest('w'), Stored: digest('b'), Found: true, Confirmed: true, Prob: 1, Value: 2, Flag: 1},
	}
	f.storage.mu.Unlock()
	f.failReads(digest('b'))
	ctx := context.Background()
	out, err := e.SubmitReport(ctx, Candidate{UID: 1001, Snapshot: []byte("multipart")})
	if err != nil || !slices.Equal(out.Pending, []uint64{1, 2}) {
		t.Fatalf("pending reservations: %+v, %v", out, err)
	}
	sent, _ := f.targetOf(t, digest('a'))
	if sent.Phase != PhaseDeletePending || sent.SentRevision != sent.Revision {
		t.Fatalf("delete journal lost on rejection: %+v", sent)
	}
	if err := e.CancelUnsent(ctx, 1001); err != nil {
		t.Fatal(err)
	}
	if got, _ := f.targetOf(t, digest('a')); !reflect.DeepEqual(got, sent) {
		t.Fatalf("sent target changed: %+v", got)
	}
	if got, _ := f.targetOf(t, digest('b')); got.T != 2 || got.Revision != 3 {
		t.Fatalf("unsent target not restored: %+v", got)
	}
	if got := f.usage(t, 1001); got != (Usage{Aliases: 1}) {
		t.Fatalf("usage after partial cancellation: %+v", got)
	}
	f.healReads()
	f.storage.mu.Lock()
	f.storage.onDelete = nil
	f.storage.mu.Unlock()
	engineTurn(t, e, func() { e.background(ctx) })
	if got, _ := f.cluster(t, 1); !slices.Equal(got.UIDs, []int{2002, 1001}) {
		t.Fatalf("sent vote not committed: %+v", got)
	}
	if got, _ := f.cluster(t, 2); !slices.Equal(got.UIDs, []int{2003}) || slices.Contains(got.Aliases, digest('w')) {
		t.Fatalf("cancelled vote committed: %+v", got)
	}
	if f.intents(t) != 0 {
		t.Fatal("completed intent retained")
	}
}

func TestCancelUnsentAfterEarlierRevisionSent(t *testing.T) {
	f := newAuditFixture(t)
	f.add(t, 1, digest('a'), 2, t0, 2002)
	e := newTestEngine(t, f)
	ctx := context.Background()
	out, err := e.SubmitReport(ctx, Candidate{UID: 1001, Snapshot: f.report("first", digest('v'), digest('a'), 1)})
	if err != nil || !slices.Equal(out.Committed, []uint64{1}) {
		t.Fatalf("first contribution: %+v, %v", out, err)
	}
	f.failReads(digest('a'))
	out, err = e.SubmitReport(ctx, Candidate{UID: 1002, Snapshot: f.report("second", digest('w'), digest('a'), 1)})
	if err != nil || !slices.Equal(out.Pending, []uint64{1}) {
		t.Fatalf("second reservation: %+v, %v", out, err)
	}
	if err := e.CancelUnsent(ctx, 1002); err != nil {
		t.Fatal(err)
	}
	if got, _ := f.targetOf(t, digest('a')); got.T != 4 || got.Revision != 4 || got.SentRevision != 2 {
		t.Fatalf("earlier send prevented cancellation: %+v", got)
	}
	if f.intents(t) != 0 || f.usage(t, 1002) != (Usage{}) {
		t.Fatal("cancelled reservation or charge retained")
	}
}

func TestCancelUnsentRechecksAfterNativeSend(t *testing.T) {
	f := newAuditFixture(t)
	f.add(t, 1, digest('a'), 2, t0, 2002)
	e := newTestEngine(t, f)
	f.failReads(digest('a'))
	ctx := context.Background()
	out, err := e.SubmitReport(ctx, Candidate{UID: 1001, Snapshot: f.report("variant", digest('v'), digest('a'), 1)})
	if err != nil || !slices.Equal(out.Pending, []uint64{1}) {
		t.Fatalf("reservation: %+v, %v", out, err)
	}
	ids, err := e.unsentReportIntents(ctx, 1001)
	if err != nil || len(ids) != 1 {
		t.Fatalf("unsent lookup: %v, %v", ids, err)
	}
	f.healReads()
	f.storage.mu.Lock()
	f.storage.onAdd = func(Digest, int32) (bool, error) { return false, ErrRejected }
	f.storage.mu.Unlock()
	engineTurn(t, e, func() {
		_, pending, err := e.publishIntent(ctx, ids[0])
		if !errors.Is(err, ErrRejected) || !slices.Equal(pending, []uint64{1}) {
			t.Errorf("rejected add: %v, %v", pending, err)
		}
		if err := e.cancelUnsent(ids); err != nil {
			t.Error(err)
		}
	})
	target, _ := f.targetOf(t, digest('a'))
	if target.T != 4 || target.SentRevision != target.Revision || target.Phase != PhaseDeletePending || f.intents(t) != 1 {
		t.Fatalf("stale lookup cancelled a journaled add: %+v", target)
	}
	if ids, err := e.unsentReportIntents(ctx, 1001); err != nil || len(ids) != 0 {
		t.Fatalf("lookup ignored changed target: %v, %v", ids, err)
	}
}

func TestCancelUnsentRollsBackOnCommitFailure(t *testing.T) {
	f := newAuditFixture(t)
	f.add(t, 1, digest('a'), 2, t0, 2002)
	fault := &transactionFault{kv: f.ledger.db}
	f.ledger.db = fault
	e := newTestEngine(t, f)
	f.failReads(digest('a'))
	ctx := context.Background()
	out, err := e.SubmitReport(ctx, Candidate{UID: 1001, Snapshot: f.report("variant", digest('v'), digest('a'), 1)})
	if err != nil || !slices.Equal(out.Pending, []uint64{1}) {
		t.Fatalf("reservation: %+v, %v", out, err)
	}
	before, _ := f.targetOf(t, digest('a'))
	engineTurn(t, e, func() {
		fault.reject = func(store.LearnTx) error { return errors.New("commit failed") }
	})
	if err := e.CancelUnsent(ctx, 1001); !errors.Is(err, ErrStateIO) {
		t.Fatalf("cancel failure: %v", err)
	}
	if got, _ := f.targetOf(t, digest('a')); !reflect.DeepEqual(got, before) || f.intents(t) != 1 || f.usage(t, 1001) != (Usage{Aliases: 1}) {
		t.Fatalf("partial cancellation escaped rollback: %+v", got)
	}
	engineTurn(t, e, func() { fault.reject = nil })
	if err := e.CancelUnsent(ctx, 1001); err != nil {
		t.Fatal(err)
	}
	if f.intents(t) != 0 || f.usage(t, 1001) != (Usage{}) {
		t.Fatal("retry failed to cancel the reservation")
	}
}

type cancelViewCounter struct {
	kv
	views int
}

func (c *cancelViewCounter) LearnView(fn func(store.LearnTx) error) error {
	c.views++
	return c.kv.LearnView(fn)
}

// An unchanged backlog must not be scanned again for each opted-out UID.
func TestCancelUnsentSharesReservationLookup(t *testing.T) {
	f := newAuditFixture(t)
	counter := &cancelViewCounter{kv: f.ledger.db}
	f.ledger.db = counter
	e := NewEngine(EngineConfig{Ledger: f.ledger})
	ctx := context.Background()
	for uid := 1001; uid <= 1010; uid++ {
		if err := e.CancelUnsent(ctx, uid); err != nil {
			t.Fatal(err)
		}
	}
	if counter.views != 1 {
		t.Fatalf("empty backlog read %d times for ten accounts, want once", counter.views)
	}
	prior := Target{Digest: digest('a'), ClusterID: 1, T: 2, Revision: 1, Phase: PhaseIdle}
	intent := Intent{ID: "new", Kind: IntentReport, UID: 1001,
		Clusters: []IntentCluster{{ClusterID: 1, Anchor: prior.Digest, Revision: 2, Prior: &prior}}}
	put := func(tx LedgerTx) error {
		target := prior
		target.Revision, target.Phase = 2, PhaseRead
		if err := tx.PutTarget(target); err != nil {
			return err
		}
		return tx.PutIntent(intent)
	}
	if err := f.ledger.Update(put); err != nil {
		t.Fatal(err)
	}
	if ids, err := e.unsentReportIntents(ctx, 1001); err != nil || !slices.Equal(ids, []string{"new"}) {
		t.Fatalf("new reservation hidden by lookup: %v, %v", ids, err)
	}
	rollback := errors.New("rollback")
	if err := f.ledger.Update(func(tx LedgerTx) error {
		if err := tx.DeleteIntent(intent.ID); err != nil {
			return err
		}
		return rollback
	}); !errors.Is(err, rollback) {
		t.Fatal(err)
	}
	if ids, err := e.unsentReportIntents(ctx, 1001); err != nil || !slices.Equal(ids, []string{"new"}) {
		t.Fatalf("rollback lost reservation: %v, %v", ids, err)
	}
	if err := f.ledger.Update(func(tx LedgerTx) error { return tx.DeleteIntent(intent.ID) }); err != nil {
		t.Fatal(err)
	}
	if err := e.CancelUnsent(ctx, 1001); err != nil {
		t.Fatalf("deleted reservation still requires the owner: %v", err)
	}
}

// Measure one opt-out pass with a backlog held by a different account.
func BenchmarkCancelUnsentPass(b *testing.B) {
	f := newAuditFixture(b)
	const accounts, pending = 1000, 1000
	if err := f.ledger.Update(func(tx LedgerTx) error {
		for i := range pending {
			id := uint64(i + 1) // #nosec G115 -- positive benchmark counter
			d := numDigest(i)
			prior := Target{Digest: d, ClusterID: id, T: 2, Revision: 1, Phase: PhaseIdle}
			intent := Intent{ID: fmt.Sprint(i), Kind: IntentReport, UID: 9000, Admitted: t0,
				Clusters: []IntentCluster{{ClusterID: id, Anchor: d, Revision: 2, NewT: 4, Prior: &prior}}}
			if err := tx.PutIntent(intent); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		b.Fatal(err)
	}
	e := NewEngine(EngineConfig{Ledger: f.ledger})
	b.ResetTimer()
	for range b.N {
		for uid := 1000; uid < 1000+accounts; uid++ {
			if err := e.CancelUnsent(context.Background(), uid); err != nil {
				b.Fatal(err)
			}
		}
	}
}
