package learn

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/pidginhost/csm/internal/antispam"
	"github.com/pidginhost/csm/internal/store"
)

var openGate = antispam.LearningGate{Install: true, Publish: true}

// failingKV refuses every write while fail is set.
type failingKV struct {
	kv
	fail atomic.Bool
}

func (f *failingKV) LearnUpdate(fn func(store.LearnTx) error) error {
	if f.fail.Load() {
		return errors.New("disk full")
	}
	return f.kv.LearnUpdate(fn)
}

// newTestEngine returns an engine over f, primed with one clean audit
// rotation and running with an open gate.
func newTestEngine(t *testing.T, f *auditFixture, gen ...string) *Engine {
	t.Helper()
	g := "gen1"
	if len(gen) > 0 {
		g = gen[0]
	}
	e := NewEngine(EngineConfig{Client: f.storage, Ledger: f.ledger, Bodies: f.bodies, HashGeneration: g, Prefix: "prefix1", Now: func() time.Time { return t0 }, TickEvery: time.Hour})
	e.pub.poll, e.pub.deadline = time.Millisecond, 20*time.Millisecond
	e.SetGate(openGate)
	e.start()
	for range 10 {
		if e.pub.FreshMatchingAllowed() {
			break
		}
		e.background(context.Background())
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		e.Run(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	return e
}

// report maps a snapshot to a near match of anchor at prob.
func (f *auditFixture) report(snapshot string, queried, anchor Digest, prob float64) []byte {
	f.storage.mu.Lock()
	defer f.storage.mu.Unlock()
	f.storage.inspect[snapshot] = []Result{{Queried: queried, Stored: anchor, Found: true, Confirmed: true, Prob: prob, Value: 2, Flag: 1}}
	return []byte(snapshot)
}

func (f *auditFixture) cluster(t *testing.T, id uint64) (Cluster, bool) {
	t.Helper()
	var c Cluster
	var ok bool
	if err := f.ledger.View(func(v LedgerView) error {
		var err error
		c, ok, err = v.Cluster(id)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return c, ok
}

func problemKeys(e *Engine) []string {
	var keys []string
	for _, p := range e.Problems() {
		keys = append(keys, p.Key)
	}
	return keys
}

func TestEngineSerializesReports(t *testing.T) {
	f := newAuditFixture(t)
	f.add(t, 1, digest('a'), 2, t0, 2002)
	e := newTestEngine(t, f)
	snaps := map[int][]byte{
		1001: f.report("variant one", digest('v'), digest('a'), 0.9),
		1003: f.report("variant two", digest('w'), digest('a'), 0.9),
	}
	var wg sync.WaitGroup
	outcomes := map[int]Outcome{}
	var mu sync.Mutex
	for uid, snap := range snaps {
		wg.Add(1)
		go func() {
			defer wg.Done()
			out, err := e.Submit(context.Background(), Candidate{UID: uid, Snapshot: snap, Ref: "ref"})
			if err != nil {
				t.Error(err)
			}
			mu.Lock()
			outcomes[uid] = out
			mu.Unlock()
		}()
	}
	wg.Wait()
	for uid, out := range outcomes {
		if !reflect.DeepEqual(out.Committed, []uint64{1}) || out.Deferred || out.Ref != "ref" {
			t.Fatalf("uid %d outcome %+v", uid, out)
		}
	}
	c, _ := f.cluster(t, 1)
	uids := slices.Clone(c.UIDs)
	slices.Sort(uids)
	if !reflect.DeepEqual(uids, []int{1001, 1003, 2002}) || len(c.Aliases) != 3 {
		t.Fatalf("cluster %+v", c)
	}
	got, _ := f.targetOf(t, digest('a'))
	if got.T != 6 || got.Revision != 3 || got.Phase != PhaseIdle {
		t.Fatalf("target %+v", got)
	}
	if v, _ := f.storage.value(digest('a')); v != 6 {
		t.Fatalf("stored %d", v)
	}
}

func TestEngineGateClosedQueuesWithoutReading(t *testing.T) {
	f := newAuditFixture(t)
	f.add(t, 1, digest('a'), 2, t0, 2002)
	e := newTestEngine(t, f)
	e.SetGate(antispam.LearningGate{Install: true})
	before, beforeBody, _, _ := f.storage.native()
	out, err := e.Submit(context.Background(), Candidate{UID: 1001, Snapshot: f.report("variant", digest('v'), digest('a'), 0.9)})
	if err != nil || !out.Deferred {
		t.Fatalf("outcome %+v err %v", out, err)
	}
	if after, afterBody, adds, deletes := f.storage.native(); after != before || afterBody != beforeBody || adds != 0 || deletes != 0 {
		t.Fatal("a closed gate let the engine call rspamd")
	}
}

func TestEngineGateInstallFalseStops(t *testing.T) {
	f := newAuditFixture(t)
	e := newTestEngine(t, f)
	snap := []byte("fresh spam")
	f.storage.bodies[string(snap)] = digest('s')
	started := make(chan struct{})
	f.storage.addWait = func(ctx context.Context) error {
		close(started)
		<-ctx.Done()
		return ErrUncertain
	}
	result := make(chan Outcome, 1)
	go func() {
		out, _ := e.Submit(context.Background(), Candidate{UID: 1001, Snapshot: snap})
		result <- out
	}()
	<-started
	e.SetGate(antispam.LearningGate{})
	select {
	case out := <-result:
		if len(out.Committed) != 0 || len(out.Pending) != 1 {
			t.Fatalf("outcome %+v", out)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("disable did not stop the add in flight")
	}
	if got, _ := f.targetOf(t, digest('s')); got.Phase != PhaseAddSent {
		t.Fatalf("uncertain add not journaled: %+v", got)
	}
	if !slices.Contains(problemKeys(e), antispam.ReasonMutationUncertain) {
		t.Fatalf("problems %v", problemKeys(e))
	}
	f.storage.addWait = nil
	_, _, adds, _ := f.storage.native()
	out, err := e.Submit(context.Background(), Candidate{UID: 1002, Snapshot: snap})
	if err != nil || !out.Deferred {
		t.Fatalf("outcome after disable %+v err %v", out, err)
	}
	if _, _, after, _ := f.storage.native(); after != adds {
		t.Fatal("a stopped engine sent an add")
	}
}

func TestEngineGateWaitsForInFlightCall(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newAuditFixture(t)
		e := newTestEngine(t, f)
		snap := []byte("synthetic spam")
		f.storage.bodies[string(snap)] = digest('s')
		started, canceled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
		f.storage.addWait = func(ctx context.Context) error {
			close(started)
			<-ctx.Done()
			close(canceled)
			<-release
			return ErrUncertain
		}
		result := make(chan Outcome, 1)
		go func() {
			out, _ := e.Submit(context.Background(), Candidate{UID: 1001, Snapshot: snap})
			result <- out
		}()
		<-started
		closed := make(chan struct{})
		go func() {
			e.SetGate(antispam.LearningGate{})
			close(closed)
		}()
		<-canceled
		synctest.Wait()
		select {
		case <-closed:
			t.Error("gate closure returned while a native call was still in flight")
		default:
		}
		close(release)
		<-closed
		out := <-result
		if len(out.Committed) != 0 || len(out.Pending) != 1 {
			t.Fatalf("canceled publication outcome %+v", out)
		}
		if got, _ := f.targetOf(t, digest('s')); got.Phase != PhaseAddSent {
			t.Fatalf("uncertain write lost its journal: %+v", got)
		}
	})
}

// Review focus 3: a write the ledger cannot commit sends no mutation.
func TestEngineStateIOStopsMutations(t *testing.T) {
	f := newAuditFixture(t)
	fail := &failingKV{kv: f.ledger.db}
	f.ledger.db = fail
	e := newTestEngine(t, f)
	snap := []byte("fresh spam")
	f.storage.bodies[string(snap)] = digest('s')
	fail.fail.Store(true)
	out, err := e.Submit(context.Background(), Candidate{UID: 1001, Snapshot: snap})
	if err == nil && out.Err == nil {
		t.Fatalf("state failure ignored: %+v", out)
	}
	if _, _, adds, deletes := f.storage.native(); adds != 0 || deletes != 0 {
		t.Fatal("sent a mutation the ledger could not journal")
	}
	if !slices.Contains(problemKeys(e), antispam.ReasonStateIO) {
		t.Fatalf("problems %v", problemKeys(e))
	}
	if entries, _ := os.ReadDir(f.bodies.Dir); len(entries) != 0 {
		t.Fatalf("left %d staged bodies", len(entries))
	}
}

func TestEngineOperatorSpamAddsMark(t *testing.T) {
	f := newAuditFixture(t)
	f.add(t, 1, digest('a'), 2, t0, 2002)
	e := newTestEngine(t, f)
	snap := f.report("operator sample", digest('a'), digest('a'), 1)
	req := OperatorRequest{Action: ActionSpam, RequestID: "0123456789abcdef0123456789abcdef", Snapshot: snap, SnapshotSHA: sha(snap)}
	res, err := e.Operator(context.Background(), req)
	if err != nil || !res.ExitOK || !reflect.DeepEqual(res.Clusters, []ClusterOutcome{{ClusterID: 1, Result: ResultCommitted}}) {
		t.Fatalf("result %+v err %v", res, err)
	}
	if got, _ := f.targetOf(t, digest('a')); got.T != 20 {
		t.Fatalf("target %+v", got)
	}
	if !reflect.DeepEqual(res.Digests, []Digest{digest('a')}) {
		t.Fatalf("audited digests %v", res.Digests)
	}
	again, err := e.Operator(context.Background(), req)
	if err != nil || !reflect.DeepEqual(again, res) {
		t.Fatalf("retry %+v err %v", again, err)
	}
	if _, _, adds, _ := f.storage.native(); adds != 1 {
		t.Fatalf("retry sent another mark: %d adds", adds)
	}
	c, _ := f.cluster(t, 1)
	if !reflect.DeepEqual(c.Marks, []string{req.RequestID}) {
		t.Fatalf("marks %v", c.Marks)
	}
}

func TestEngineOperatorCancelKeepsRequestForRetry(t *testing.T) {
	f := newAuditFixture(t)
	f.add(t, 1, digest('a'), 2, t0, 2002)
	e := newTestEngine(t, f)
	snap := f.report("operator sample", digest('a'), digest('a'), 1)
	req := OperatorRequest{Action: ActionSpam, RequestID: "0123456789abcdef0123456789abcdef", Snapshot: snap, SnapshotSHA: sha(snap)}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	f.storage.onInspect = cancel
	res, err := e.Operator(ctx, req)
	if err != nil && !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if errors.Is(err, context.Canceled) && (res.RequestID != req.RequestID || len(res.Clusters) != 0 || res.ExitOK) {
		t.Fatalf("canceled caller received an unfinished result: %+v", res)
	}
	// The owner finishes and records the operation even after its caller
	// stops waiting. Retrying the same request must not add another mark.
	if err = e.do(context.Background(), func() {}); err != nil {
		t.Fatal(err)
	}
	f.storage.onInspect = nil
	res, err = e.Operator(context.Background(), req)
	if err != nil || !res.ExitOK || !reflect.DeepEqual(res.Clusters, []ClusterOutcome{{ClusterID: 1, Result: ResultCommitted}}) {
		t.Fatalf("retry result %+v err %v", res, err)
	}
	if _, _, adds, _ := f.storage.native(); adds != 1 {
		t.Fatalf("retry sent another mark: %d adds", adds)
	}
}

func TestEngineSubmitCancelKeepsContribution(t *testing.T) {
	f := newAuditFixture(t)
	f.add(t, 1, digest('a'), 2, t0, 2002)
	e := newTestEngine(t, f)
	c := Candidate{UID: 1001, Snapshot: f.report("report sample", digest('a'), digest('a'), 1), Ref: "report"}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	f.storage.onInspect = cancel
	out, err := e.Submit(ctx, c)
	if err != nil && !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if errors.Is(err, context.Canceled) && (out.Ref != c.Ref || !out.Deferred || len(out.Committed) != 0) {
		t.Fatalf("canceled caller received an unfinished result: %+v", out)
	}
	if err = e.do(context.Background(), func() {}); err != nil {
		t.Fatal(err)
	}
	f.storage.onInspect = nil
	first := out
	// Cancellation may land before the reservation or after it. A reserved
	// contribution survives and the next background turn finishes it.
	engineTurn(t, e, func() { e.background(context.Background()) })
	out, err = e.Submit(context.Background(), c)
	committedOnce := reflect.DeepEqual(out.Duplicates, []uint64{1}) && len(out.Committed) == 0 ||
		len(first.Committed) == 0 && reflect.DeepEqual(out.Committed, []uint64{1})
	if err != nil || !committedOnce {
		t.Fatalf("first %+v, retry %+v err %v", first, out, err)
	}
	if _, _, adds, _ := f.storage.native(); adds != 1 {
		t.Fatalf("cancel and retry sent %d contributions", adds)
	}
	if c, _ := f.cluster(t, 1); countOf(c.UIDs, 1001) != 1 {
		t.Fatalf("vote counted twice: %v", c.UIDs)
	}
}

func TestEngineForgetZeroTargetsAndRemovesBody(t *testing.T) {
	f := newAuditFixture(t)
	f.add(t, 1, digest('a'), 4, t0, 2002, 2003)
	e := newTestEngine(t, f)
	snap := f.report("forget me", digest('v'), digest('a'), 0.9)
	res, err := e.Operator(context.Background(), OperatorRequest{Action: ActionForget, RequestID: "fedcba9876543210fedcba9876543210", Snapshot: snap, SnapshotSHA: sha(snap)})
	if err != nil || !res.ExitOK || !reflect.DeepEqual(res.Clusters, []ClusterOutcome{{ClusterID: 1, Result: ResultForgotten}}) {
		t.Fatalf("result %+v err %v", res, err)
	}
	if _, ok := f.storage.value(digest('a')); ok {
		t.Fatal("forgotten anchor still stored")
	}
	if got, ok := f.targetOf(t, digest('a')); !ok || got.T != 0 {
		t.Fatalf("zero-target guard missing: %+v", got)
	}
	if _, err := os.Stat(filepath.Join(f.bodies.Dir, BodyName(1))); !os.IsNotExist(err) {
		t.Fatal("anchor body left after forget")
	}
	if _, ok := f.cluster(t, 1); ok {
		t.Fatal("cluster record left after forget")
	}
}

func TestEngineForgetNoMatchOnlyAfterCompleteCheck(t *testing.T) {
	f := newAuditFixture(t)
	e := newTestEngine(t, f)
	snap := []byte("never reported")
	f.storage.bodies[string(snap)] = digest('n')
	req := OperatorRequest{Action: ActionForget, RequestID: "00112233445566778899aabbccddeeff", Snapshot: snap, SnapshotSHA: sha(snap)}
	f.storage.readErr = errors.New("timeout")
	if res, err := e.Operator(context.Background(), req); err == nil || res.ExitOK || res.Outcome == ResultNoMatch {
		t.Fatalf("an outage read as no-match: %+v err %v", res, err)
	}
	f.storage.readErr = nil
	res, err := e.Operator(context.Background(), req)
	if err != nil || !res.ExitOK || res.Outcome != ResultNoMatch {
		t.Fatalf("result %+v err %v", res, err)
	}
}

func TestEngineProblemsStableKeys(t *testing.T) {
	f := newAuditFixture(t)
	f.add(t, 1, digest('a'), 2, t0, 2002)
	e := newTestEngine(t, f)
	f.storage.readErr = errors.New("timeout")
	for range RequestErrorPasses {
		if _, err := e.Submit(context.Background(), Candidate{UID: 1001, Snapshot: []byte("x")}); err != nil {
			t.Fatal(err)
		}
	}
	first := e.Problems()
	if !slices.Contains(problemKeys(e), antispam.ReasonRequestErrors) {
		t.Fatalf("problems %+v", first)
	}
	if !reflect.DeepEqual(first, e.Problems()) {
		t.Fatal("problems are not stable between reads")
	}
	seen := map[string]bool{}
	for _, p := range first {
		if p.Code != antispam.CodeLearning || p.Severity != antispam.Warning || seen[p.Key] || p.Detail == "" {
			t.Fatalf("problem %+v", p)
		}
		seen[p.Key] = true
	}
	f.storage.readErr = nil
	if _, err := e.Submit(context.Background(), Candidate{UID: 1001, Snapshot: f.report("variant", digest('v'), digest('a'), 0.9)}); err != nil {
		t.Fatal(err)
	}
	if slices.Contains(problemKeys(e), antispam.ReasonRequestErrors) {
		t.Fatal("request errors not cleared after a success")
	}
}

// A ledger bound to other hash keys freezes admissions.
func TestEngineBindMismatchFreezes(t *testing.T) {
	f := newAuditFixture(t)
	e := newTestEngine(t, f, "other")
	out, err := e.Submit(context.Background(), Candidate{UID: 1001, Snapshot: []byte("x")})
	if err != nil || !out.Deferred {
		t.Fatalf("outcome %+v err %v", out, err)
	}
	if !slices.Contains(problemKeys(e), antispam.ReasonStateMismatch) {
		t.Fatalf("problems %v", problemKeys(e))
	}
	if _, bodies, _, _ := f.storage.native(); bodies != 0 {
		t.Fatal("a mismatched ledger read a report")
	}
}

// A deferred request is not final: the same ID runs again later.
func TestEngineOperatorDeferredIsNotRecorded(t *testing.T) {
	f := newAuditFixture(t)
	f.add(t, 1, digest('a'), 2, t0, 2002)
	e := newTestEngine(t, f)
	snap := f.report("operator sample", digest('a'), digest('a'), 1)
	req := OperatorRequest{Action: ActionSpam, RequestID: "0123456789abcdef0123456789abcdef", Snapshot: snap, SnapshotSHA: sha(snap)}
	// The anchor has an unfinished publication: the request waits.
	if err := f.ledger.Update(func(tx LedgerTx) error {
		return tx.PutTarget(Target{Digest: digest('a'), ClusterID: 1, T: 2, Revision: 1, Phase: PhaseRead})
	}); err != nil {
		t.Fatal(err)
	}
	res, err := e.Operator(context.Background(), req)
	if err != nil || res.ExitOK || res.Outcome != ResultDeferred || len(res.Clusters) != 0 {
		t.Fatalf("result %+v err %v", res, err)
	}
	if err = f.ledger.Update(func(tx LedgerTx) error {
		return tx.PutTarget(Target{Digest: digest('a'), ClusterID: 1, T: 2, Revision: 1, Phase: PhaseIdle})
	}); err != nil {
		t.Fatal(err)
	}
	res, err = e.Operator(context.Background(), req)
	if err != nil || !res.ExitOK || !reflect.DeepEqual(res.Clusters, []ClusterOutcome{{ClusterID: 1, Result: ResultCommitted}}) {
		t.Fatalf("retry %+v err %v", res, err)
	}
}

// A retry that finishes a partial request still reports the parts the first
// attempt skipped.
func TestEngineOperatorRetryKeepsSkippedParts(t *testing.T) {
	f := newAuditFixture(t)
	f.add(t, 1, digest('a'), 2, t0, 2002)
	f.add(t, 2, digest('b'), 2, t0, 2002)
	e := newTestEngine(t, f)
	snap := []byte("two parts")
	f.storage.mu.Lock()
	f.storage.inspect[string(snap)] = []Result{
		{Queried: digest('v'), Stored: digest('a'), Found: true, Confirmed: true, Prob: 0.9, Value: 2, Flag: 1},
		{Queried: digest('w'), Stored: digest('b'), Found: true, Confirmed: true, Prob: 0.5, Value: 2, Flag: 1},
	}
	f.storage.mu.Unlock()
	f.storage.onAdd = func(Digest, int32) (bool, error) { return true, ErrUncertain }
	req := OperatorRequest{Action: ActionSpam, RequestID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Snapshot: snap, SnapshotSHA: sha(snap)}
	if res, err := e.Operator(context.Background(), req); err != nil || res.Outcome != ResultPending {
		t.Fatalf("first %+v err %v", res, err)
	}
	f.storage.onAdd = nil
	res, err := e.Operator(context.Background(), req)
	want := []ClusterOutcome{{ClusterID: 1, Result: ResultCommitted}, {Result: ResultSkipped + ":" + SkipBelowJoin}}
	if err != nil || res.ExitOK || res.Outcome != ResultPartial || !reflect.DeepEqual(res.Clusters, want) {
		t.Fatalf("retry %+v err %v", res, err)
	}
}

// Review focus 4: a request ID is bound to its file; reuse with other bytes
// fails and changes nothing.
func TestLearnSameIDDifferentSnapshotFails(t *testing.T) {
	f := newAuditFixture(t)
	f.add(t, 1, digest('a'), 2, t0, 2002)
	e := newTestEngine(t, f)
	snap := f.report("operator sample", digest('a'), digest('a'), 1)
	req := OperatorRequest{Action: ActionSpam, RequestID: "0123456789abcdef0123456789abcdef", Snapshot: snap, SnapshotSHA: sha(snap)}
	if _, err := e.Operator(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	other := f.report("another sample", digest('a'), digest('a'), 1)
	changed := OperatorRequest{Action: ActionSpam, RequestID: req.RequestID, Snapshot: other, SnapshotSHA: sha(other)}
	if _, err := e.Operator(context.Background(), changed); !errors.Is(err, ErrRequestReused) {
		t.Fatalf("err %v", err)
	}
	forget := req
	forget.Action = ActionForget
	if _, err := e.Operator(context.Background(), forget); !errors.Is(err, ErrRequestReused) {
		t.Fatalf("action change: err %v", err)
	}
	if got, _ := f.targetOf(t, digest('a')); got.T != 20 {
		t.Fatalf("target %+v", got)
	}
}

// A new cluster replacing a zero-target guard takes over the digest; the
// guard's charge goes back to its account.
func TestEngineSeedOverGuardCreditsGuard(t *testing.T) {
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
	snap := []byte("fresh spam")
	f.storage.bodies[string(snap)] = digest('s')
	out, err := e.Submit(context.Background(), Candidate{UID: 1002, Snapshot: snap})
	if err != nil || len(out.Committed) != 1 {
		t.Fatalf("outcome %+v err %v", out, err)
	}
	got, _ := f.targetOf(t, digest('s'))
	if got.T != 2 || got.Revision != 4 || got.GuardCharge != nil {
		t.Fatalf("target %+v", got)
	}
	if err := f.ledger.View(func(v LedgerView) error {
		old, err := v.Usage(1001, false)
		if err != nil {
			return err
		}
		if old != (Usage{}) {
			t.Errorf("guard charge kept: %+v", old)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func countOf(xs []int, x int) int {
	n := 0
	for _, v := range xs {
		if v == x {
			n++
		}
	}
	return n
}

// Review fix: the daemon pauses the learner around every reconcile pass. A
// routine pause loses no verified target, so it must not make new clusters
// wait for another full audit rotation; a real gate closure still does.
func TestEnginePauseKeepsFreshMatching(t *testing.T) {
	f := newAuditFixture(t)
	f.add(t, 1, digest('a'), 2, t0, 2002)
	e := newTestEngine(t, f)
	e.Pause()
	if e.Publishing() {
		t.Fatal("a paused learner still publishes")
	}
	e.SetGate(openGate)
	snap := []byte("fresh spam")
	f.storage.bodies[string(snap)] = digest('s')
	out, err := e.Submit(context.Background(), Candidate{UID: 1001, Snapshot: snap})
	if err != nil || out.Deferred || !reflect.DeepEqual(out.Committed, []uint64{2}) {
		t.Fatalf("a routine pause blocked a new cluster: %+v err %v", out, err)
	}
	e.SetGate(antispam.LearningGate{Install: true})
	e.SetGate(openGate)
	other := []byte("other spam")
	f.storage.bodies[string(other)] = digest('o')
	out, err = e.Submit(context.Background(), Candidate{UID: 1001, Snapshot: other})
	if err != nil || !out.Deferred {
		t.Fatalf("a real closure did not owe an audit rotation: %+v err %v", out, err)
	}
}
