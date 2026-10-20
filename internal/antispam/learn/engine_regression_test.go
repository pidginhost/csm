package learn

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/pidginhost/csm/internal/antispam"
	"github.com/pidginhost/csm/internal/store"
)

// transactionFault rejects a transaction after its writes, before commit.
type transactionFault struct {
	kv
	reject func(store.LearnTx) error
}

func (f *transactionFault) LearnUpdate(fn func(store.LearnTx) error) error {
	return f.kv.LearnUpdate(func(tx store.LearnTx) error {
		if err := fn(tx); err != nil {
			return err
		}
		if f.reject != nil {
			return f.reject(tx)
		}
		return nil
	})
}

type inspectionHook struct {
	nativeClient
	inspect func(context.Context, []byte) (Inspection, error)
}

func (c inspectionHook) Inspect(ctx context.Context, body []byte) (Inspection, error) {
	return c.inspect(ctx, body)
}

func engineTurn(t *testing.T, e *Engine, fn func()) {
	t.Helper()
	if err := e.do(context.Background(), fn); err != nil {
		t.Fatal(err)
	}
}

func operatorRecord(t *testing.T, l *Ledger, id string) OpRecord {
	t.Helper()
	var o OpRecord
	if err := l.View(func(v LedgerView) error {
		var err error
		o, _, err = v.Op(id)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return o
}

func opRequest(action string, body []byte) OperatorRequest {
	return OperatorRequest{Action: action, RequestID: "0123456789abcdef0123456789abcdef", Snapshot: body, SnapshotSHA: sha(body)}
}

func TestEngineCancelledCallerWaitsForSnapshotRelease(t *testing.T) {
	for _, operator := range []bool{false, true} {
		t.Run(map[bool]string{false: "report", true: "operator"}[operator], func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				f := newAuditFixture(t)
				e := newTestEngine(t, f)
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				var released atomic.Bool
				client := inspectionHook{nativeClient: f.storage, inspect: func(context.Context, []byte) (Inspection, error) {
					cancel()
					time.Sleep(time.Second)
					released.Store(true)
					return Inspection{}, context.Canceled
				}}
				engineTurn(t, e, func() { e.cfg.Client = client; e.pub.client = client })
				var err error
				if operator {
					_, err = e.Operator(ctx, opRequest(ActionSpam, []byte("sample")))
				} else {
					_, err = e.SubmitReport(ctx, Candidate{UID: 1001, Snapshot: []byte("sample")})
				}
				if !errors.Is(err, context.Canceled) || !released.Load() {
					t.Errorf("returned before releasing caller snapshot: released=%v err=%v", released.Load(), err)
				}
			})
		})
	}
}

func TestEngineGateClosureStopsAdmissionAfterInspection(t *testing.T) {
	f := newAuditFixture(t)
	e := newTestEngine(t, f)
	snap := []byte("fresh sample")
	f.storage.bodies[string(snap)] = digest('a')
	client := inspectionHook{nativeClient: f.storage, inspect: func(ctx context.Context, b []byte) (Inspection, error) {
		result, err := f.storage.Inspect(ctx, b)
		setGateFromHook(e, antispam.LearningGate{})
		return result, err
	}}
	engineTurn(t, e, func() { e.cfg.Client = client; e.pub.client = client })
	out, err := e.SubmitReport(context.Background(), Candidate{UID: 1001, Snapshot: snap})
	if err != nil || !out.Deferred || len(out.Pending) != 0 {
		t.Errorf("admitted after gate closure: %+v err=%v", out, err)
	}
	entries, err := os.ReadDir(f.bodies.Dir)
	if err != nil || len(entries) != 0 {
		t.Errorf("staged a body after gate closure: %d err=%v", len(entries), err)
	}
}

func TestEngineGateClosureStopsCallsAfterSend(t *testing.T) {
	f := newAuditFixture(t)
	e := newTestEngine(t, f)
	snap := []byte("fresh sample")
	f.storage.bodies[string(snap)] = digest('a')
	f.storage.onAdd = func(Digest, int32) (bool, error) {
		setGateFromHook(e, antispam.LearningGate{Install: true})
		return true, nil
	}
	out, err := e.SubmitReport(context.Background(), Candidate{UID: 1001, Snapshot: snap})
	if err != nil || !reflect.DeepEqual(out.Pending, []uint64{1}) {
		t.Fatalf("outcome %+v err=%v", out, err)
	}
	f.storage.mu.Lock()
	defer f.storage.mu.Unlock()
	if f.storage.syncs != 0 {
		t.Errorf("sent %d syncs after gate closure", f.storage.syncs)
	}
}

func TestEngineClosedStartupRetainsOrphanBodies(t *testing.T) {
	f := newAuditFixture(t)
	staged, err := f.bodies.Stage([]byte("orphan"))
	if err != nil {
		t.Fatal(err)
	}
	e := NewEngine(EngineConfig{Client: f.storage, Ledger: f.ledger, Bodies: f.bodies, HashGeneration: "gen1", Prefix: "prefix1", TickEvery: time.Hour})
	ctx, cancel := context.WithCancel(context.Background())
	go e.Run(ctx)
	t.Cleanup(func() { cancel(); <-e.done })
	engineTurn(t, e, func() {})
	if _, err := os.Stat(filepath.Join(f.bodies.Dir, staged.Name)); err != nil {
		t.Fatalf("disabled startup removed retained body: %v", err)
	}
}

func TestEnginePendingVoteBlocksReadmission(t *testing.T) {
	f := newAuditFixture(t)
	f.add(t, 1, digest('a'), 2, t0, 2002)
	fault := &transactionFault{kv: f.ledger.db}
	f.ledger.db = fault
	e := newTestEngine(t, f)
	snap := f.report("alias", digest('a'), digest('a'), 1)
	engineTurn(t, e, func() {
		fault.reject = func(tx store.LearnTx) error {
			data, err := tx.Get(store.LearnClustersBucket, clusterKey(1))
			if err != nil {
				return err
			}
			var c Cluster
			if err = json.Unmarshal(data, &c); err != nil {
				return err
			}
			if slices.Contains(c.UIDs, 1001) {
				return errors.New("commit failed")
			}
			return nil
		}
	})
	out, err := e.SubmitReport(context.Background(), Candidate{UID: 1001, Snapshot: snap})
	if err != nil || !errors.Is(out.Err, ErrStateIO) || !reflect.DeepEqual(out.Pending, []uint64{1}) {
		t.Fatalf("first outcome %+v err=%v", out, err)
	}
	engineTurn(t, e, func() { fault.reject = nil })
	out, err = e.SubmitReport(context.Background(), Candidate{UID: 1001, Snapshot: snap})
	if err != nil || !out.Deferred {
		t.Errorf("uncommitted vote admitted again: %+v err=%v", out, err)
	}
	target, _ := f.targetOf(t, digest('a'))
	if target.T != 4 {
		t.Errorf("one UID raised target twice: %d", target.T)
	}
	engineTurn(t, e, func() { e.background(context.Background()) })
	c, _ := f.cluster(t, 1)
	if !reflect.DeepEqual(c.UIDs, []int{2002, 1001}) {
		t.Errorf("votes %v", c.UIDs)
	}
}

func TestEngineBackgroundRecordsOperatorCompletion(t *testing.T) {
	for _, action := range []string{ActionSpam, ActionForget} {
		t.Run(action, func(t *testing.T) {
			f := newAuditFixture(t)
			f.add(t, 1, digest('a'), 2, t0, 2002)
			e := newTestEngine(t, f)
			req := opRequest(action, f.report("sample", digest('v'), digest('a'), 1))
			f.storage.onAdd = func(Digest, int32) (bool, error) { return true, ErrUncertain }
			f.storage.onDelete = func(Digest) (bool, error) { return true, ErrUncertain }
			first, err := e.Operator(context.Background(), req)
			if err != nil || first.Outcome != ResultPending {
				t.Fatalf("first %+v err=%v", first, err)
			}
			f.storage.onAdd = nil
			f.storage.onDelete = nil
			engineTurn(t, e, func() { e.background(context.Background()) })
			rec := operatorRecord(t, f.ledger, req.RequestID)
			want := ResultCommitted
			if action == ActionForget {
				want = ResultForgotten
			}
			if !rec.Done || rec.Outcome == nil || !reflect.DeepEqual(rec.Outcome.Clusters, []ClusterOutcome{{ClusterID: 1, Result: want}}) {
				t.Errorf("background lost completion: %+v", rec)
			}
			// A later inspection resolves to a different cluster. The retry must
			// return its original outcome without inspecting or mutating again.
			f.add(t, 2, digest('b'), 2, t0, 2003)
			f.report("sample", digest('v'), digest('b'), 1)
			before, bodyBefore, adds, deletes := f.storage.native()
			again, err := e.Operator(context.Background(), req)
			if err != nil || !again.ExitOK || !reflect.DeepEqual(again.Clusters, []ClusterOutcome{{ClusterID: 1, Result: want}}) {
				t.Errorf("retry %+v err=%v", again, err)
			}
			after, bodyAfter, addsAfter, deletesAfter := f.storage.native()
			if before != after || bodyBefore != bodyAfter || adds != addsAfter || deletes != deletesAfter {
				t.Error("completed retry did new native work")
			}
		})
	}
}

func TestEngineOperatorCompletionIsAtomicWithVote(t *testing.T) {
	f := newAuditFixture(t)
	f.add(t, 1, digest('a'), 2, t0, 2002)
	fault := &transactionFault{kv: f.ledger.db}
	f.ledger.db = fault
	e := newTestEngine(t, f)
	req := opRequest(ActionSpam, f.report("sample", digest('v'), digest('a'), 1))
	engineTurn(t, e, func() {
		fault.reject = func(tx store.LearnTx) error {
			data, err := tx.Get(store.LearnOpsBucket, []byte(req.RequestID))
			if err != nil || data == nil {
				return err
			}
			var op OpRecord
			if err = json.Unmarshal(data, &op); err != nil {
				return err
			}
			if op.Done {
				return errors.New("outcome commit failed")
			}
			return nil
		}
	})
	if _, err := e.Operator(context.Background(), req); !errors.Is(err, ErrStateIO) {
		t.Fatalf("expected outcome commit failure: %v", err)
	}
	if _, _, adds, _ := f.storage.native(); adds != 1 {
		t.Fatalf("native write did not precede the failed commit: %d adds", adds)
	}
	c, _ := f.cluster(t, 1)
	if len(c.Marks) != 0 {
		t.Error("mark committed without its durable outcome")
	}
	engineTurn(t, e, func() { fault.reject = nil })
	got, err := e.Operator(context.Background(), req)
	if err != nil || !got.ExitOK || !reflect.DeepEqual(got.Clusters, []ClusterOutcome{{ClusterID: 1, Result: ResultCommitted}}) {
		t.Fatalf("retry %+v err=%v", got, err)
	}
	_, _, adds, _ := f.storage.native()
	if adds != 1 {
		t.Fatalf("retry sent %d adds", adds)
	}
}

func TestEngineOperatorDuplicateIsSuccessful(t *testing.T) {
	f := newAuditFixture(t)
	f.add(t, 1, digest('a'), 20, t0, 2002)
	e := newTestEngine(t, f)
	req := opRequest(ActionSpam, f.report("sample", digest('a'), digest('a'), 1))
	if err := f.ledger.Update(func(tx LedgerTx) error {
		c, _, err := tx.Cluster(1)
		if err != nil {
			return err
		}
		c.Marks = []string{req.RequestID}
		return tx.PutCluster(c)
	}); err != nil {
		t.Fatal(err)
	}
	got, err := e.Operator(context.Background(), req)
	if err != nil || !got.ExitOK || got.Outcome != ResultDuplicate || !reflect.DeepEqual(got.Clusters, []ClusterOutcome{{ClusterID: 1, Result: ResultDuplicate}}) {
		t.Fatalf("duplicate %+v err=%v", got, err)
	}
}

func TestEngineForgetMissWaitsForCurrentLedger(t *testing.T) {
	f := newAuditFixture(t)
	f.add(t, 1, digest('a'), 2, t0, 2002)
	e := newTestEngine(t, f)
	snap := []byte("unaccepted variant")
	f.storage.bodies[string(snap)] = digest('v')
	engineTurn(t, e, func() { e.pub.owe("") })
	req := opRequest(ActionForget, snap)
	got, err := e.Operator(context.Background(), req)
	if err != nil || got.ExitOK || got.Outcome != ResultDeferred {
		t.Fatalf("stale no-match %+v err=%v", got, err)
	}
	if operatorRecord(t, f.ledger, req.RequestID).Done {
		t.Fatal("stale miss recorded as final")
	}
	engineTurn(t, e, func() { e.background(context.Background()) })
	got, err = e.Operator(context.Background(), req)
	if err != nil || !got.ExitOK || got.Outcome != ResultNoMatch {
		t.Fatalf("current miss %+v err=%v", got, err)
	}
}

func TestEngineForgetCleanupFailureRemainsPending(t *testing.T) {
	f := newAuditFixture(t)
	f.add(t, 1, digest('a'), 2, t0, 2002)
	e := newTestEngine(t, f)
	req := opRequest(ActionForget, f.report("sample", digest('a'), digest('a'), 1))
	// Deleting the native anchor succeeds, but body-directory safety fails.
	f.storage.onDelete = func(Digest) (bool, error) { return true, os.Chmod(f.bodies.Dir, 0o755) }
	t.Cleanup(func() { _ = os.Chmod(f.bodies.Dir, 0o700) })
	got, err := e.Operator(context.Background(), req)
	if err != nil || got.Outcome != ResultPending {
		t.Fatalf("first %+v err=%v", got, err)
	}
	if !slices.Contains(problemKeys(e), antispam.ReasonStateIO) {
		t.Error("body unlink failure did not report state_io")
	}
	engineTurn(t, e, func() { e.background(context.Background()) })
	if rec := operatorRecord(t, f.ledger, req.RequestID); rec.Done {
		t.Fatal("completed while body still exists")
	}
	if _, statErr := os.Stat(filepath.Join(f.bodies.Dir, BodyName(1))); statErr != nil {
		t.Fatalf("lost cleanup reference body: %v", statErr)
	}
	f.storage.onDelete = nil
	if err = os.Chmod(f.bodies.Dir, 0o700); err != nil {
		t.Fatal(err)
	}
	engineTurn(t, e, func() { e.background(context.Background()) })
	got, err = e.Operator(context.Background(), req)
	if err != nil || !got.ExitOK || got.Outcome != ResultForgotten {
		t.Fatalf("retry %+v err=%v", got, err)
	}
	if _, statErr := os.Stat(filepath.Join(f.bodies.Dir, BodyName(1))); !os.IsNotExist(statErr) {
		t.Fatalf("body remains: %v", statErr)
	}
}

func TestEngineRetiresBeforeAdmittingExpiredCluster(t *testing.T) {
	f := newAuditFixture(t)
	f.add(t, 1, digest('a'), 2, t0, 2002)
	e := newTestEngine(t, f)
	engineTurn(t, e, func() { e.cfg.Now = func() time.Time { return t0.Add(Retention) }; e.pub.now = e.cfg.Now })
	out, err := e.SubmitReport(context.Background(), Candidate{UID: 1001, Snapshot: f.report("sample", digest('v'), digest('a'), 1)})
	if err != nil || !out.Deferred || len(out.Committed) != 0 {
		t.Errorf("expired cluster admitted report: %+v err=%v", out, err)
	}
	target, _ := f.targetOf(t, digest('a'))
	if target.T != 0 {
		t.Errorf("expired target retained at %d", target.T)
	}
}

func TestEngineRetirementPublishesDespiteCleanupFailure(t *testing.T) {
	for name, recovered := range map[string]bool{"running": true, "recovery pending": false} {
		t.Run(name, func(t *testing.T) {
			f := newAuditFixture(t)
			f.add(t, 1, digest('a'), 2, t0, 2002)
			e := newTestEngine(t, f)
			if err := os.Chmod(f.bodies.Dir, 0o755); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.Chmod(f.bodies.Dir, 0o700) })
			engineTurn(t, e, func() {
				e.recovered = recovered
				e.cfg.Now = func() time.Time { return t0.Add(Retention) }
				e.pub.now = e.cfg.Now
				e.background(context.Background())
				e.refresh()
			})
			if v, present := f.storage.value(digest('a')); present {
				t.Errorf("expired anchor still scores %d after body cleanup failed", v)
			}
			if target, _ := f.targetOf(t, digest('a')); target.T != 0 || target.Phase != PhaseIdle {
				t.Errorf("retirement was not published: %+v", target)
			}
			if c, ok := f.cluster(t, 1); !ok || !c.Retired {
				t.Fatal("lost the pending body cleanup reference")
			}
			body := filepath.Join(f.bodies.Dir, BodyName(1))
			if _, err := os.Stat(body); err != nil {
				t.Fatalf("body changed during failed cleanup: %v", err)
			}
			if !slices.Contains(problemKeys(e), antispam.ReasonStateIO) {
				t.Fatal("cleanup failure was not reported")
			}
			if err := os.Chmod(f.bodies.Dir, 0o700); err != nil {
				t.Fatal(err)
			}
			engineTurn(t, e, func() { e.background(context.Background()); e.refresh() })
			if _, ok := f.cluster(t, 1); ok {
				t.Fatal("cleanup did not finish after recovery")
			}
			if _, err := os.Stat(body); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("body remains after cleanup: %v", err)
			}
			if slices.Contains(problemKeys(e), antispam.ReasonStateIO) {
				t.Fatal("cleanup warning stayed after recovery")
			}
		})
	}
}

func TestEngineReenableRequiresFreshAudit(t *testing.T) {
	f := newAuditFixture(t)
	f.add(t, 1, digest('a'), 2, t0, 2002)
	e := newTestEngine(t, f)
	e.SetGate(antispam.LearningGate{})
	f.storage.mu.Lock()
	delete(f.storage.values, digest('a'))
	f.storage.mu.Unlock()
	snap := []byte("variant during rebuild")
	f.storage.bodies[string(snap)] = digest('v')
	e.SetGate(openGate)
	got, err := e.SubmitReport(context.Background(), Candidate{UID: 1001, Snapshot: snap})
	if err != nil || !got.Deferred || len(got.Committed) != 0 {
		t.Fatalf("seeded before reenable audit: %+v err=%v", got, err)
	}
}

func TestEngineOperatorRequestFailuresCountPasses(t *testing.T) {
	for _, action := range []string{ActionSpam, ActionForget} {
		t.Run(action, func(t *testing.T) {
			f := newAuditFixture(t)
			e := newTestEngine(t, f)
			f.storage.readErr = errors.New("unavailable")
			req := opRequest(action, []byte("sample"))
			for pass := 1; pass <= RequestErrorPasses; pass++ {
				if _, err := e.Operator(context.Background(), req); !errors.Is(err, ErrReadFailed) {
					t.Fatalf("err=%v", err)
				}
				if got := slices.Contains(problemKeys(e), antispam.ReasonRequestErrors); got != (pass == RequestErrorPasses) {
					t.Fatalf("pass %d warning=%v", pass, got)
				}
			}
		})
	}
}

func TestEngineGateClosureStopsBodyCommitAndCleanup(t *testing.T) {
	t.Run("staging", func(t *testing.T) {
		f := newAuditFixture(t)
		e := newTestEngine(t, f)
		snap := []byte("new anchor")
		f.storage.bodies[string(snap)] = digest('a')
		f.bodies.writeFile = func(file *os.File, b []byte) error {
			setGateFromHook(e, antispam.LearningGate{})
			return writeSync(file, b)
		}
		got, err := e.SubmitReport(context.Background(), Candidate{UID: 1001, Snapshot: snap})
		if err != nil || !got.Deferred || len(got.Pending) != 0 {
			t.Errorf("reserved after gate closed during staging: %+v err=%v", got, err)
		}
		if _, statErr := os.Stat(filepath.Join(f.bodies.Dir, BodyName(1))); !os.IsNotExist(statErr) {
			t.Errorf("committed body after closure: %v", statErr)
		}
		f.bodies.writeFile = nil
		e.SetGate(openGate)
		engineTurn(t, e, func() { e.background(context.Background()) })
		entries, err := os.ReadDir(f.bodies.Dir)
		if err != nil || len(entries) != 0 {
			t.Errorf("unreserved body not recovered: %d err=%v", len(entries), err)
		}
	})
	t.Run("retirement", func(t *testing.T) {
		f := newAuditFixture(t)
		f.add(t, 1, digest('a'), 2, t0, 2002)
		fault := &transactionFault{kv: f.ledger.db}
		f.ledger.db = fault
		e := newTestEngine(t, f)
		engineTurn(t, e, func() {
			e.cfg.Now = func() time.Time { return t0.Add(Retention) }
			e.pub.now = e.cfg.Now
			fault.reject = func(tx store.LearnTx) error {
				data, err := tx.Get(store.LearnClustersBucket, clusterKey(1))
				if err != nil || data == nil {
					return err
				}
				var c Cluster
				if err = json.Unmarshal(data, &c); err != nil {
					return err
				}
				if c.Retired {
					setGateFromHook(e, antispam.LearningGate{})
				}
				return nil
			}
		})
		_, _ = e.SubmitReport(context.Background(), Candidate{UID: 1001, Snapshot: []byte("sample")})
		if _, statErr := os.Stat(filepath.Join(f.bodies.Dir, BodyName(1))); statErr != nil {
			t.Fatalf("unlinked after gate closure: %v", statErr)
		}
	})
}

func TestEngineRecordedOutcomeNeedsNoWrites(t *testing.T) {
	f := newAuditFixture(t)
	f.add(t, 1, digest('a'), 2, t0, 2002)
	fault := &failingKV{kv: f.ledger.db}
	f.ledger.db = fault
	e := newTestEngine(t, f)
	req := opRequest(ActionSpam, f.report("sample", digest('a'), digest('a'), 1))
	first, err := e.Operator(context.Background(), req)
	if err != nil || !first.ExitOK {
		t.Fatalf("first %+v err=%v", first, err)
	}
	fault.fail.Store(true)
	again, err := e.Operator(context.Background(), req)
	if err != nil || !reflect.DeepEqual(again, first) {
		t.Fatalf("durable outcome unavailable without a write: %+v err=%v", again, err)
	}
}

func TestEngineMultipartCompletionSurvivesRestart(t *testing.T) {
	f := newAuditFixture(t)
	f.add(t, 1, digest('a'), 2, t0, 2002)
	f.add(t, 2, digest('b'), 2, t0, 2003)
	f.add(t, 3, digest('c'), 2, t0, 2004)
	cfg := EngineConfig{Client: f.storage, Ledger: f.ledger, Bodies: f.bodies, HashGeneration: "gen1", Prefix: "prefix1", Now: func() time.Time { return t0 }}
	e := NewEngine(cfg)
	e.SetGate(openGate)
	e.background(context.Background())
	snap := []byte("multipart sample")
	f.storage.inspect[string(snap)] = []Result{
		{Queried: digest('v'), Stored: digest('a'), Found: true, Confirmed: true, Prob: 1, Value: 2, Flag: 1},
		{Queried: digest('w'), Stored: digest('b'), Found: true, Confirmed: true, Prob: 1, Value: 2, Flag: 1},
		{Queried: digest('x'), Stored: digest('c'), Found: true, Confirmed: true, Prob: 0.5, Value: 2, Flag: 1},
	}
	f.storage.onAdd = func(d Digest, _ int32) (bool, error) {
		if d == digest('b') {
			return true, ErrUncertain
		}
		return true, nil
	}
	req := opRequest(ActionSpam, snap)
	first, err := e.operator(context.Background(), req)
	want := []ClusterOutcome{{ClusterID: 1, Result: ResultCommitted}, {ClusterID: 2, Result: ResultPending}, {Result: ResultSkipped + ":" + SkipBelowJoin}}
	if err != nil || !reflect.DeepEqual(first.Clusters, want) {
		t.Fatalf("first %+v err=%v", first, err)
	}
	f.storage.onAdd = nil
	restarted := NewEngine(cfg)
	restarted.SetGate(openGate)
	restarted.background(context.Background())
	f.storage.readErr = errors.New("retry must not reinspect")
	got, err := restarted.operator(context.Background(), req)
	want[1].Result = ResultCommitted
	if err != nil || got.ExitOK || got.Outcome != ResultPartial || !reflect.DeepEqual(got.Clusters, want) {
		t.Fatalf("restart %+v err=%v", got, err)
	}
	if _, _, adds, _ := f.storage.native(); adds != 2 {
		t.Fatalf("replayed %d adds", adds)
	}
}

func TestEngineRequestIDBinding(t *testing.T) {
	f := newAuditFixture(t)
	e := newTestEngine(t, f)
	snap := []byte("empty inspection")
	f.storage.inspect[string(snap)] = nil
	req := opRequest(ActionSpam, snap)
	if _, err := e.Operator(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	before, bodyBefore, adds, deletes := f.storage.native()
	changedAction := req
	changedAction.Action = ActionForget
	changedBody := req
	changedBody.Snapshot = []byte("other sample")
	changedBody.SnapshotSHA = sha(changedBody.Snapshot)
	for _, changed := range []OperatorRequest{changedAction, changedBody} {
		if _, err := e.Operator(context.Background(), changed); !errors.Is(err, ErrRequestReused) {
			t.Fatalf("changed request err=%v", err)
		}
	}
	after, bodyAfter, addsAfter, deletesAfter := f.storage.native()
	if before != after || bodyBefore != bodyAfter || adds != addsAfter || deletes != deletesAfter {
		t.Fatal("reused ID did native work")
	}
}

func TestEngineForgetReportsUnmatchedParts(t *testing.T) {
	f := newAuditFixture(t)
	f.add(t, 1, digest('a'), 2, t0, 2002)
	e := newTestEngine(t, f)
	snap := []byte("mixed forget sample")
	f.storage.inspect[string(snap)] = []Result{
		{Queried: digest('a'), Stored: digest('a'), Found: true, Confirmed: true, Prob: 1, Value: 2, Flag: 1},
		{Queried: digest('v')},
	}
	got, err := e.Operator(context.Background(), opRequest(ActionForget, snap))
	want := []ClusterOutcome{{ClusterID: 1, Result: ResultForgotten}, {Result: ResultNoMatch}}
	if err != nil || !got.ExitOK || got.Outcome != ResultForgotten || !reflect.DeepEqual(got.Clusters, want) {
		t.Fatalf("missing part outcome: %+v err=%v", got, err)
	}
}

func TestEngineCancellationDoesNotReportBackendFailure(t *testing.T) {
	f := newAuditFixture(t)
	e := newTestEngine(t, f)
	for range RequestErrorPasses {
		ctx, cancel := context.WithCancel(context.Background())
		client := inspectionHook{nativeClient: f.storage, inspect: func(context.Context, []byte) (Inspection, error) { cancel(); return Inspection{}, context.Canceled }}
		engineTurn(t, e, func() { e.cfg.Client = client; e.pub.client = client })
		_, err := e.SubmitReport(ctx, Candidate{UID: 1001, Snapshot: []byte("sample")})
		cancel()
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancel err=%v", err)
		}
	}
	if slices.Contains(problemKeys(e), antispam.ReasonRequestErrors) {
		t.Fatal("caller cancellations reported as backend failures")
	}
}

func TestEngineForgetTerminatesSupersededOperatorMark(t *testing.T) {
	f := newAuditFixture(t)
	f.add(t, 1, digest('a'), 2, t0, 2002)
	e := newTestEngine(t, f)
	snap := f.report("sample", digest('a'), digest('a'), 1)
	req := opRequest(ActionSpam, snap)
	f.storage.onAdd = func(Digest, int32) (bool, error) { return true, ErrUncertain }
	if got, err := e.Operator(context.Background(), req); err != nil || got.Outcome != ResultPending {
		t.Fatalf("first %+v err=%v", got, err)
	}
	f.storage.onAdd = nil
	forget := req
	forget.RequestID = "fedcba9876543210fedcba9876543210"
	forget.Action = ActionForget
	if got, err := e.Operator(context.Background(), forget); err != nil || got.Outcome != ResultForgotten {
		t.Fatalf("forget %+v err=%v", got, err)
	}
	engineTurn(t, e, func() { e.background(context.Background()) })
	f.storage.mu.Lock()
	delete(f.storage.inspect, string(snap))
	f.storage.bodies[string(snap)] = digest('a')
	f.storage.mu.Unlock()
	if got, err := e.SubmitReport(context.Background(), Candidate{UID: 1003, Snapshot: snap}); err != nil || !reflect.DeepEqual(got.Committed, []uint64{2}) {
		t.Fatalf("new cluster %+v err=%v", got, err)
	}
	_, _, before, _ := f.storage.native()
	got, err := e.Operator(context.Background(), req)
	want := []ClusterOutcome{{ClusterID: 1, Result: ResultSkipped + ":superseded"}}
	if err != nil || got.ExitOK || got.Outcome != ResultSkipped || !reflect.DeepEqual(got.Clusters, want) {
		t.Fatalf("old mark resumed: %+v err=%v", got, err)
	}
	c, _ := f.cluster(t, 2)
	if _, _, after, _ := f.storage.native(); after != before || len(c.Marks) != 0 {
		t.Fatalf("old mark affected new cluster: %+v", c)
	}
}

// setGateFromHook changes the gate the way a reconcile pass does, from
// another goroutine, and returns once it applies. Hooks run on the engine
// goroutine, which SetGate's drain waits for.
func setGateFromHook(e *Engine, g antispam.LearningGate) {
	go e.SetGate(g)
	for {
		e.mu.Lock()
		applied := e.gate == g
		e.mu.Unlock()
		if applied {
			return
		}
		runtime.Gosched()
	}
}
