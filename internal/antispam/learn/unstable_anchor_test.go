package learn

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// Failure to inspect the stored bytes is not proof that their digest changed,
// even if a different representation can be inspected successfully.
func TestUnstableAnchorInspectionFailurePreservesCluster(t *testing.T) {
	for _, failure := range []error{context.DeadlineExceeded, ErrInspectionFailed, ErrMessageRejected} {
		for _, fallback := range []Digest{digest('a'), digest('b')} {
			t.Run(fmt.Sprintf("%s/%s", failure, shortDigest(fallback)), func(t *testing.T) {
				f := newAuditFixture(t)
				body := []byte(pdfMessage)
				s := stageCommit(t, f.bodies, body, 1)
				anchor := digest('a')
				if err := f.ledger.Update(func(tx LedgerTx) error {
					if err := tx.PutCluster(Cluster{ID: 1, Anchor: anchor, BodyLen: s.Len, BodySHA: s.SHA}); err != nil {
						return err
					}
					return tx.PutTarget(Target{Digest: anchor, ClusterID: 1, T: 4, Revision: 1, Phase: PhaseRead})
				}); err != nil {
					t.Fatal(err)
				}
				f.storage.set(anchor, 2)
				text := textOnlyMessage(body)
				f.storage.bodies[string(text)] = fallback
				p := f.publisher()
				inspections, warnings := 0, 0
				p.client = inspectionHook{nativeClient: f.storage, inspect: func(ctx context.Context, got []byte) (Inspection, error) {
					inspections++
					if bytes.Equal(got, body) {
						return Inspection{}, failure
					}
					return f.storage.Inspect(ctx, got)
				}}
				p.onUnstable = func(string) { warnings++ }
				res, err := p.Turn(context.Background(), anchor)
				if !errors.Is(err, ErrReadFailed) || !errors.Is(err, failure) || res.Done || res.Uncertain {
					t.Fatalf("result %+v err %v", res, err)
				}
				if inspections != 1 || warnings != 0 {
					t.Fatalf("inspections %d warnings %d", inspections, warnings)
				}
				if c, ok := f.cluster(t, 1); !ok || c.Retired {
					t.Fatalf("cluster %+v present %v", c, ok)
				}
				if target, _ := f.targetOf(t, anchor); target.T != 4 || target.Revision != 1 || target.Phase != PhaseRead {
					t.Fatalf("target %+v", target)
				}
				if adds, deletes := f.storage.counts(); len(adds) != 0 || deletes != 0 {
					t.Fatalf("adds %v deletes %d", adds, deletes)
				}
			})
		}
	}
}

// A seed retired before its first contribution still owns its retained body
// and permanent guard. Repeating unstable reports must consume the allowance.
func TestUnstableAnchorSeedKeepsChargesUntilCleanup(t *testing.T) {
	for _, operator := range []bool{false, true} {
		t.Run(fmt.Sprint(operator), func(t *testing.T) {
			f := newAuditFixture(t)
			body := []byte("unstable seed")
			f.storage.bodies[string(body)] = digest('a')
			inspections := 0
			e, stop := startTestEngineWith(t, f, func(cfg *EngineConfig) {
				cfg.Client = inspectionHook{nativeClient: f.storage, inspect: func(ctx context.Context, got []byte) (Inspection, error) {
					inspections++
					if inspections > 1 {
						return inspection(Result{Queried: digest('b')}), nil
					}
					return f.storage.Inspect(ctx, got)
				}}
			})
			t.Cleanup(stop)
			uid := 1001
			if operator {
				uid = 0
				req := opRequest(ActionSpam, body)
				for range 2 {
					res, err := e.Operator(context.Background(), req)
					want := []ClusterOutcome{{ClusterID: 1, Result: ResultSkipped + ":superseded"}}
					if err != nil || res.ExitOK || res.Outcome != ResultSkipped || !reflect.DeepEqual(res.Clusters, want) {
						t.Fatalf("operator result %+v err %v", res, err)
					}
				}
			} else {
				out, err := e.SubmitReport(context.Background(), Candidate{UID: uid, Snapshot: body})
				if err != nil || out.Err != nil || out.Deferred || len(out.Committed) != 0 || len(out.Pending) != 0 {
					t.Fatalf("report %+v err %v", out, err)
				}
			}
			stop()
			guard, ok := f.targetOf(t, digest('a'))
			wantGuard := &Charge{UID: uid, Operator: operator, Usage: Usage{Aliases: 1}}
			if !ok || guard.T != 0 || guard.Phase != PhaseIdle || !reflect.DeepEqual(guard.GuardCharge, wantGuard) {
				t.Errorf("guard %+v present %v", guard, ok)
			}
			checkUsage := func(want Usage) {
				t.Helper()
				if err := f.ledger.View(func(v LedgerView) error {
					u, err := v.Usage(uid, operator)
					if u != want {
						t.Errorf("usage %+v want %+v", u, want)
					}
					return err
				}); err != nil {
					t.Fatal(err)
				}
			}
			checkUsage(Usage{BodyBytes: int64(len(body)), Aliases: 1})
			if c, ok := f.cluster(t, 1); !ok || !c.Retired || len(c.UIDs) != 0 || len(c.Marks) != 0 {
				t.Fatalf("cluster %+v present %v", c, ok)
			}
			// A cleanup failure must not release the body allowance.
			if err := os.Chmod(f.bodies.Dir, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := e.pub.cleanup(context.Background()); !errors.Is(err, ErrStateIO) {
				t.Fatalf("cleanup err %v", err)
			}
			checkUsage(Usage{BodyBytes: int64(len(body)), Aliases: 1})
			if err := os.Chmod(f.bodies.Dir, 0o700); err != nil {
				t.Fatal(err)
			}
			// Recovery repeats cleanup without crediting the guard.
			f.reopen(t)
			for range 2 {
				if _, err := f.publisher().RepairTurn(context.Background(), RepairBatch); err != nil {
					t.Fatal(err)
				}
			}
			checkUsage(Usage{Aliases: 1})
			if _, ok := f.cluster(t, 1); ok {
				t.Fatal("retired cluster survived cleanup")
			}
			if _, err := os.Stat(filepath.Join(f.bodies.Dir, BodyName(1))); !os.IsNotExist(err) {
				t.Fatalf("retired body survived cleanup: %v", err)
			}
		})
	}
}

func TestUnstableAnchorTargetMovementDoesNotRetire(t *testing.T) {
	for _, field := range []string{"revision", "value", "phase"} {
		t.Run(field, func(t *testing.T) {
			f := newPublishFixture(t, 4)
			seen := f.target(t)
			f.storage.bodies[string(f.body)] = digest('b')
			f.storage.onInspect = func() {
				f.editTarget(t, func(cur *Target) {
					switch field {
					case "revision":
						cur.Revision++
					case "value":
						cur.T++
					case "phase":
						cur.Phase = PhaseAddSent
					}
				})
			}
			p := f.publisher()
			warnings := 0
			p.onUnstable = func(string) { warnings++ }
			if verified, err := p.sendAdd(context.Background(), seen, 0); verified || !errors.Is(err, errAnchorRetired) {
				t.Fatalf("verified %v err %v", verified, err)
			}
			if got := f.target(t); got.T == 0 || warnings != 0 {
				t.Fatalf("target %+v warnings %d", got, warnings)
			}
			if err := f.ledger.View(func(v LedgerView) error {
				c, ok, err := v.Cluster(1)
				if !ok || c.Retired {
					t.Errorf("moved cluster %+v present %v", c, ok)
				}
				return err
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
	// Even repeated movement cannot keep one turn on the owner indefinitely.
	f := newPublishFixture(t, 4)
	f.storage.bodies[string(f.body)] = digest('b')
	f.storage.onInspect = func() { f.editTarget(t, func(cur *Target) { cur.Revision++ }) }
	p := f.publisher()
	res, err := p.Turn(context.Background(), f.anchor)
	if err != nil || res.Done || res.Uncertain || f.target(t).T != 4 {
		t.Fatalf("result %+v err %v target %+v", res, err, f.target(t))
	}
	if _, inspected, adds, deletes := f.storage.native(); inspected != p.attempts || adds != 0 || deletes != 0 {
		t.Fatalf("inspections %d adds %d deletes %d", inspected, adds, deletes)
	}
}

func TestUnstableAnchorReporterCannotReplaceStoredBody(t *testing.T) {
	f := newAuditFixture(t)
	f.add(t, 1, digest('a'), UIDWeight, t0, 1001)
	e := newTestEngine(t, f)
	body := f.report("different reporter's variant", digest('b'), digest('a'), 0.9)
	f.storage.bodies[string(body)] = digest('b')
	out, err := e.SubmitReport(context.Background(), Candidate{UID: 1002, Snapshot: body})
	if err != nil || out.Err != nil || !reflect.DeepEqual(out.Committed, []uint64{1}) {
		t.Fatalf("report %+v err %v", out, err)
	}
	c, ok := f.cluster(t, 1)
	if !ok || c.Retired || !reflect.DeepEqual(c.UIDs, []int{1001, 1002}) {
		t.Fatalf("cluster %+v present %v", c, ok)
	}
	if adds, deletes := f.storage.counts(); !reflect.DeepEqual(adds, []int32{UIDWeight}) || deletes != 0 {
		t.Fatalf("adds %v deletes %d", adds, deletes)
	}
	if v, ok := f.storage.value(digest('a')); !ok || v != 2*UIDWeight {
		t.Fatalf("original anchor value %d present %v", v, ok)
	}
	if _, ok := f.storage.value(digest('b')); ok {
		t.Fatal("published the reporter's replacement body")
	}
}

func TestUnstableAnchorJoinRecoversWithoutVote(t *testing.T) {
	f := newAuditFixture(t)
	f.add(t, 1, digest('a'), UIDWeight, t0, 1001)
	f.add(t, 2, digest('c'), UIDWeight, t0, 1003)
	e, stop := startTestEngine(t, f)
	t.Cleanup(stop)
	c, _ := f.cluster(t, 1)
	body, err := f.bodies.Read(c.ID, c.BodyLen, c.BodySHA)
	if err != nil {
		t.Fatal(err)
	}
	f.storage.bodies[string(body)] = digest('b')
	f.storage.onDelete = func(Digest) (bool, error) { return false, ErrRejected }
	out, err := e.SubmitReport(context.Background(), Candidate{UID: 1002,
		Snapshot: f.report("joins unstable anchor", digest('d'), digest('a'), 0.9)})
	if err != nil || !errors.Is(out.Err, ErrRejected) || len(out.Committed) != 0 || !reflect.DeepEqual(out.Pending, []uint64{1}) {
		t.Fatalf("report %+v err %v", out, err)
	}
	stop()
	c, ok := f.cluster(t, 1)
	if !ok || !c.Retired || !reflect.DeepEqual(c.UIDs, []int{1001}) {
		t.Fatalf("retired cluster %+v present %v", c, ok)
	}
	f.storage.onDelete = nil
	f.reopen(t)
	e = newTestEngine(t, f)
	if _, ok := f.storage.value(digest('a')); ok {
		t.Fatal("restart did not delete the retired score")
	}
	if _, ok := f.cluster(t, 1); ok {
		t.Fatal("restart did not clean up the retired cluster")
	}
	if ids, lookupErr := e.ReportUIDs(context.Background()); lookupErr != nil || len(ids) != 0 {
		t.Fatalf("pending reporters %v err %v", ids, lookupErr)
	}
	if err = f.ledger.View(func(v LedgerView) error {
		for uid, want := range map[int]Usage{1001: {Aliases: 1}, 1002: {}} {
			got, usageErr := v.Usage(uid, false)
			if usageErr != nil {
				return usageErr
			}
			if got != want {
				t.Errorf("uid %d usage %+v want %+v", uid, got, want)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	out, err = e.SubmitReport(context.Background(), Candidate{UID: 1002,
		Snapshot: f.report("joins stable anchor", digest('e'), digest('c'), 0.9)})
	if err != nil || out.Err != nil || !reflect.DeepEqual(out.Committed, []uint64{2}) {
		t.Fatalf("stable report %+v err %v", out, err)
	}
}

func TestUnstableAnchorForgetNeedsNoBodyInspection(t *testing.T) {
	f := newAuditFixture(t)
	f.add(t, 1, digest('a'), UIDWeight, t0, 1001)
	e := newTestEngine(t, f)
	snapshot := f.report("forget sample", digest('a'), digest('a'), 1)
	// Only the request body can be inspected. Deletion must use the digest.
	engineTurn(t, e, func() {
		e.pub.client = inspectionHook{nativeClient: f.storage, inspect: func(context.Context, []byte) (Inspection, error) {
			t.Error("forget inspected the retired body")
			return Inspection{}, ErrInspectionFailed
		}}
	})
	req := opRequest(ActionForget, snapshot)
	for range 2 {
		res, err := e.Operator(context.Background(), req)
		if err != nil || !res.ExitOK || res.Outcome != ResultForgotten {
			t.Fatalf("forget %+v err %v", res, err)
		}
	}
	if adds, deletes := f.storage.counts(); len(adds) != 0 || deletes != 1 {
		t.Fatalf("adds %v deletes %d", adds, deletes)
	}
}

func TestUnstableAnchorChangedGenerationCannotRetire(t *testing.T) {
	f := newAuditFixture(t)
	f.add(t, 1, digest('a'), UIDWeight, t0, 1001)
	f.storage.set(digest('a'), 1)
	e := newTestEngine(t, f, "changed-generation")
	out, err := e.SubmitReport(context.Background(), Candidate{UID: 1002, Snapshot: []byte("report")})
	if err != nil || !errors.Is(out.Err, ErrStateMismatch) || !out.Deferred {
		t.Fatalf("report %+v err %v", out, err)
	}
	if c, ok := f.cluster(t, 1); !ok || c.Retired {
		t.Fatalf("cluster %+v present %v", c, ok)
	}
	if reads, inspected, adds, deletes := f.storage.native(); reads != 0 || inspected != 0 || adds != 0 || deletes != 0 {
		t.Fatalf("reads %d inspections %d adds %d deletes %d", reads, inspected, adds, deletes)
	}
}

// A failed retirement commit must keep the reservation's entire charge and
// emit no warning. After retry, cleanup may run before the intent is resumed.
func TestUnstableAnchorRetirementChargeTransferIsAtomic(t *testing.T) {
	f := newAuditFixture(t)
	body := []byte("pending unstable seed")
	f.storage.bodies[string(body)] = digest('a')
	inspections := 0
	e, stop := startTestEngineWith(t, f, func(cfg *EngineConfig) {
		cfg.Client = inspectionHook{nativeClient: f.storage, inspect: func(ctx context.Context, body []byte) (Inspection, error) {
			inspections++
			if inspections > 1 {
				return Inspection{}, ErrInspectionFailed
			}
			return f.storage.Inspect(ctx, body)
		}}
	})
	t.Cleanup(stop)
	out, err := e.SubmitReport(context.Background(), Candidate{UID: 1001, Snapshot: body})
	if err != nil || !errors.Is(out.Err, ErrReadFailed) || !reflect.DeepEqual(out.Pending, []uint64{1}) {
		t.Fatalf("report %+v err %v", out, err)
	}
	stop()
	f.storage.bodies[string(body)] = digest('b')
	base := f.ledger.db
	f.ledger.db = &publishFaultLedger{kv: base, updateErr: errors.New("commit failed")}
	p := f.publisher()
	warnings := 0
	p.onUnstable = func(string) { warnings++ }
	res, err := p.Turn(context.Background(), digest('a'))
	if !errors.Is(err, ErrStateIO) || res.Done || warnings != 0 {
		t.Fatalf("result %+v err %v warnings %d", res, err, warnings)
	}
	if c, ok := f.cluster(t, 1); !ok || c.Retired || len(c.Charges) != 0 {
		t.Fatalf("failed transaction changed cluster %+v present %v", c, ok)
	}
	ids, err := f.ledger.reportIntents(context.Background(), 1001)
	if err != nil || len(ids) != 1 {
		t.Fatalf("intents %v err %v", ids, err)
	}
	if err = f.ledger.View(func(v LedgerView) error {
		i, ok, readErr := v.Intent(ids[0])
		if !ok || i.Seed == nil || !reflect.DeepEqual(i.Clusters[0].Aliases, []Digest{digest('a')}) {
			t.Errorf("failed transaction changed intent %+v", i)
		}
		return readErr
	}); err != nil {
		t.Fatal(err)
	}
	f.ledger.db = base
	if res, err = p.Turn(context.Background(), digest('a')); err != nil || !res.Done || warnings != 1 {
		t.Fatalf("retry result %+v err %v warnings %d", res, err, warnings)
	}
	if err = p.cleanup(context.Background()); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err = e.resume(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if err = f.ledger.View(func(v LedgerView) error {
		u, readErr := v.Usage(1001, false)
		if u != (Usage{Aliases: 1}) {
			t.Errorf("charge refunded more than once: %+v", u)
		}
		return readErr
	}); err != nil {
		t.Fatal(err)
	}
	if ids, err = f.ledger.reportIntents(context.Background(), 1001); err != nil || len(ids) != 0 {
		t.Fatalf("completed intents %v err %v", ids, err)
	}
}
