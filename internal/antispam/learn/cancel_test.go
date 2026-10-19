package learn

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"testing"

	"github.com/pidginhost/csm/internal/store"
)

// Spec 5 and 7.4: an observed opt-out cancels the account's reservations
// that sent nothing under their revision; sent ones keep publishing.

func (f *auditFixture) failReads(d Digest) {
	f.storage.mu.Lock()
	defer f.storage.mu.Unlock()
	f.storage.failRead = func(ds []Digest) error {
		if slices.Contains(ds, d) {
			return errors.New("backend down")
		}
		return nil
	}
}

func (f *auditFixture) healReads() {
	f.storage.mu.Lock()
	defer f.storage.mu.Unlock()
	f.storage.failRead, f.storage.syncErr = nil, nil
}

func (f *auditFixture) usage(t *testing.T, uid int) Usage {
	t.Helper()
	var u Usage
	if err := f.ledger.View(func(v LedgerView) error {
		var err error
		u, err = v.Usage(uid, false)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return u
}

func (f *auditFixture) intents(t *testing.T) int {
	t.Helper()
	n := 0
	if err := f.ledger.View(func(v LedgerView) error {
		return v.tx.ForEach(store.LearnIntentsBucket, func(_, _ []byte) error { n++; return nil })
	}); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestEngineCancelUnsentRestoresJoinedTarget(t *testing.T) {
	f := newAuditFixture(t)
	f.add(t, 1, digest('a'), 2, t0, 2002)
	e := newTestEngine(t, f)
	ctx := context.Background()
	f.failReads(digest('a'))
	out, _ := e.SubmitReport(ctx, Candidate{UID: 1001, Snapshot: f.report("variant", digest('v'), digest('a'), 0.9)})
	if !reflect.DeepEqual(out.Pending, []uint64{1}) {
		t.Fatalf("reservation not left unsent: %+v", out)
	}
	f.healReads()
	if err := e.CancelUnsent(ctx, 1003); err != nil {
		t.Fatal(err)
	}
	if got, _ := f.targetOf(t, digest('a')); got.T != 4 || f.intents(t) != 1 {
		t.Fatalf("another account's opt-out changed the reservation: %+v", got)
	}
	if err := e.CancelUnsent(ctx, 1001); err != nil {
		t.Fatal(err)
	}
	if got, _ := f.targetOf(t, digest('a')); got.T != 2 || got.Revision != 3 {
		t.Fatalf("target not restored: %+v", got)
	}
	if n := f.intents(t); n != 0 {
		t.Fatalf("%d intents left", n)
	}
	if u := f.usage(t, 1001); u != (Usage{}) {
		t.Fatalf("cancelled reservation still charged: %+v", u)
	}
	engineTurn(t, e, func() { e.background(ctx) })
	if got, _ := f.targetOf(t, digest('a')); got.T != 2 || got.Phase != PhaseIdle {
		t.Fatalf("restored target not verified: %+v", got)
	}
	if _, _, adds, _ := f.storage.native(); adds != 0 {
		t.Fatalf("cancelled reservation sent %d adds", adds)
	}
	if v, _ := f.storage.value(digest('a')); v != 2 {
		t.Fatalf("stored value %d", v)
	}
	if c, _ := f.cluster(t, 1); !reflect.DeepEqual(c.UIDs, []int{2002}) || slices.Contains(c.Aliases, digest('v')) {
		t.Fatalf("cancelled vote counted: %+v", c)
	}
}

func TestEngineCancelUnsentKeepsSentContribution(t *testing.T) {
	f := newAuditFixture(t)
	f.add(t, 1, digest('a'), 2, t0, 2002)
	e := newTestEngine(t, f)
	ctx := context.Background()
	f.storage.mu.Lock()
	f.storage.syncErr = errors.New("flush reply lost")
	f.storage.mu.Unlock()
	out, _ := e.SubmitReport(ctx, Candidate{UID: 1001, Snapshot: f.report("variant", digest('v'), digest('a'), 0.9)})
	if !reflect.DeepEqual(out.Pending, []uint64{1}) {
		t.Fatalf("add not left uncertain: %+v", out)
	}
	f.healReads()
	if err := e.CancelUnsent(ctx, 1001); err != nil {
		t.Fatal(err)
	}
	if got, _ := f.targetOf(t, digest('a')); got.T != 4 || f.intents(t) != 1 {
		t.Fatalf("sent reservation cancelled: %+v", got)
	}
	engineTurn(t, e, func() { e.background(ctx) })
	if c, _ := f.cluster(t, 1); !reflect.DeepEqual(c.UIDs, []int{2002, 1001}) {
		t.Fatalf("sent contribution not committed: %v", c.UIDs)
	}
}

// A verified add whose commit failed is sent work, even after an audit
// queues its target for another check.
func TestEngineCancelUnsentKeepsVerifiedContribution(t *testing.T) {
	f := newAuditFixture(t)
	f.add(t, 1, digest('a'), 2, t0, 2002)
	fault := &transactionFault{kv: f.ledger.db}
	f.ledger.db = fault
	e := newTestEngine(t, f)
	ctx := context.Background()
	engineTurn(t, e, func() {
		fault.reject = func(tx store.LearnTx) error {
			c, _, err := (LedgerView{tx: tx}).Cluster(1)
			if err == nil && slices.Contains(c.UIDs, 1001) {
				return errors.New("commit failed")
			}
			return err
		}
	})
	out, _ := e.SubmitReport(ctx, Candidate{UID: 1001, Snapshot: f.report("variant", digest('v'), digest('a'), 0.9)})
	if !errors.Is(out.Err, ErrStateIO) || !reflect.DeepEqual(out.Pending, []uint64{1}) {
		t.Fatalf("commit did not fail: %+v", out)
	}
	engineTurn(t, e, func() { fault.reject = nil })
	if err := f.ledger.Update(func(tx LedgerTx) error {
		tg, _, err := tx.Target(digest('a'))
		if err != nil {
			return err
		}
		tg.Phase = PhaseRead
		return tx.PutTarget(tg)
	}); err != nil {
		t.Fatal(err)
	}
	if err := e.CancelUnsent(ctx, 1001); err != nil {
		t.Fatal(err)
	}
	if got, _ := f.targetOf(t, digest('a')); got.T != 4 || f.intents(t) != 1 {
		t.Fatalf("verified contribution cancelled: %+v", got)
	}
	engineTurn(t, e, func() { e.background(ctx) })
	if c, _ := f.cluster(t, 1); !reflect.DeepEqual(c.UIDs, []int{2002, 1001}) {
		t.Fatalf("verified contribution not committed: %v", c.UIDs)
	}
}

func TestEngineCancelUnsentRestoresReplacedGuard(t *testing.T) {
	f := newAuditFixture(t)
	guard := &Charge{UID: 1001, Usage: Usage{Aliases: 1}}
	if err := f.ledger.Update(func(tx LedgerTx) error {
		if err := tx.AddUsage(1001, false, guard.Usage); err != nil {
			return err
		}
		return tx.PutTarget(Target{Digest: digest('s'), ClusterID: 9, T: 0, Revision: 3, Phase: PhaseIdle, GuardCharge: guard})
	}); err != nil {
		t.Fatal(err)
	}
	e := newTestEngine(t, f)
	ctx := context.Background()
	snap := []byte("fresh spam")
	f.storage.bodies[string(snap)] = digest('s')
	f.failReads(digest('s'))
	out, _ := e.SubmitReport(ctx, Candidate{UID: 1002, Snapshot: snap})
	if len(out.Pending) != 1 {
		t.Fatalf("seed not left unsent: %+v", out)
	}
	seed := out.Pending[0]
	f.healReads()
	if err := e.CancelUnsent(ctx, 1002); err != nil {
		t.Fatal(err)
	}
	got, _ := f.targetOf(t, digest('s'))
	if got.T != 0 || got.ClusterID != 9 || got.Revision != 5 || !reflect.DeepEqual(got.GuardCharge, guard) {
		t.Fatalf("guard not restored: %+v", got)
	}
	if u := f.usage(t, 1001); u != guard.Usage {
		t.Fatalf("guard owner usage %+v", u)
	}
	if u := f.usage(t, 1002); u != (Usage{}) {
		t.Fatalf("cancelled seed still charged: %+v", u)
	}
	engineTurn(t, e, func() { e.background(ctx) })
	if got, _ := f.targetOf(t, digest('s')); got.Phase != PhaseIdle || got.T != 0 {
		t.Fatalf("guard not verified: %+v", got)
	}
	if _, ok := f.cluster(t, seed); ok {
		t.Fatal("cancelled seed cluster kept")
	}
	if _, err := os.Stat(filepath.Join(f.bodies.Dir, BodyName(seed))); !os.IsNotExist(err) {
		t.Fatalf("cancelled seed body kept: %v", err)
	}
	if _, _, adds, _ := f.storage.native(); adds != 0 {
		t.Fatalf("cancelled seed sent %d adds", adds)
	}
}

func TestEngineCancelUnsentDropsNewSeed(t *testing.T) {
	f := newAuditFixture(t)
	e := newTestEngine(t, f)
	ctx := context.Background()
	snap := []byte("fresh spam")
	f.storage.bodies[string(snap)] = digest('s')
	f.failReads(digest('s'))
	out, _ := e.SubmitReport(ctx, Candidate{UID: 1002, Snapshot: snap})
	if len(out.Pending) != 1 {
		t.Fatalf("seed not left unsent: %+v", out)
	}
	f.healReads()
	if err := e.CancelUnsent(ctx, 1002); err != nil {
		t.Fatal(err)
	}
	if got, ok := f.targetOf(t, digest('s')); ok {
		t.Fatalf("unsent seed left a target: %+v", got)
	}
	if u := f.usage(t, 1002); u != (Usage{}) {
		t.Fatalf("cancelled seed still charged: %+v", u)
	}
	engineTurn(t, e, func() { e.background(ctx) })
	if _, ok := f.cluster(t, out.Pending[0]); ok {
		t.Fatal("cancelled seed cluster kept")
	}
	// The digest stays free for a new report.
	out, err := e.SubmitReport(ctx, Candidate{UID: 1003, Snapshot: snap})
	if err != nil || len(out.Committed) != 1 {
		t.Fatalf("new seed after cancel: %+v err %v", out, err)
	}
}

func TestEngineCancelUnsentKeepsCommittedClusters(t *testing.T) {
	f := newAuditFixture(t)
	f.add(t, 1, digest('a'), 2, t0, 2002)
	f.add(t, 2, digest('b'), 2, t0, 2003)
	e := newTestEngine(t, f)
	ctx := context.Background()
	snap := []byte("multipart sample")
	f.storage.inspect[string(snap)] = []Result{
		{Queried: digest('v'), Stored: digest('a'), Found: true, Confirmed: true, Prob: 1, Value: 2, Flag: 1},
		{Queried: digest('w'), Stored: digest('b'), Found: true, Confirmed: true, Prob: 1, Value: 2, Flag: 1},
	}
	f.failReads(digest('b'))
	out, _ := e.SubmitReport(ctx, Candidate{UID: 1001, Snapshot: snap})
	if !reflect.DeepEqual(out.Committed, []uint64{1}) || !reflect.DeepEqual(out.Pending, []uint64{2}) {
		t.Fatalf("outcome %+v", out)
	}
	f.healReads()
	if err := e.CancelUnsent(ctx, 1001); err != nil {
		t.Fatal(err)
	}
	if got, _ := f.targetOf(t, digest('b')); got.T != 2 || f.intents(t) != 0 {
		t.Fatalf("unsent cluster not cancelled: %+v", got)
	}
	if u := f.usage(t, 1001); u != (Usage{Aliases: 1}) {
		t.Fatalf("usage %+v, want the committed cluster's alias only", u)
	}
	engineTurn(t, e, func() { e.background(ctx) })
	if c, _ := f.cluster(t, 1); !reflect.DeepEqual(c.UIDs, []int{2002, 1001}) {
		t.Fatalf("committed vote lost: %v", c.UIDs)
	}
	if c, _ := f.cluster(t, 2); !reflect.DeepEqual(c.UIDs, []int{2003}) {
		t.Fatalf("cancelled vote counted: %v", c.UIDs)
	}
	if v, _ := f.storage.value(digest('b')); v != 2 {
		t.Fatalf("cancelled cluster stored %d", v)
	}
}

// An account with nothing reserved needs no turn from the owner.
func TestEngineCancelUnsentWithoutReservationsSkipsOwner(t *testing.T) {
	f := newAuditFixture(t)
	e, stop := startTestEngine(t, f)
	stop()
	if err := e.CancelUnsent(context.Background(), 1001); err != nil {
		t.Fatal(err)
	}
}

func TestEngineReportUIDsListsReservationHolders(t *testing.T) {
	f := newAuditFixture(t)
	f.add(t, 1, digest('a'), 2, t0, 2002)
	e := newTestEngine(t, f)
	ctx := context.Background()
	f.failReads(digest('a'))
	if out, _ := e.SubmitReport(ctx, Candidate{UID: 1001, Snapshot: f.report("variant", digest('v'), digest('a'), 0.9)}); len(out.Pending) != 1 {
		t.Fatalf("reservation not left pending: %+v", out)
	}
	if uids, err := e.ReportUIDs(ctx); err != nil || !slices.Equal(uids, []int{1001}) {
		t.Fatalf("holders %v err %v", uids, err)
	}
	f.healReads()
	engineTurn(t, e, func() { e.background(ctx) })
	if uids, err := e.ReportUIDs(ctx); err != nil || len(uids) != 0 {
		t.Fatalf("committed reservation still listed: %v err %v", uids, err)
	}
}
