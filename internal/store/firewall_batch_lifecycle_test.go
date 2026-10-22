package store

import (
	"bytes"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/firewall"
	bolt "go.etcd.io/bbolt"
)

// boundaryStore loses one write the lifecycle makes: a transition to failTo,
// or an audit acknowledgement. The write is refused before it commits, so
// the journal is left exactly as a crash at that point leaves it.
type boundaryStore struct {
	*DB
	failTo  string
	failAck bool
}

var errBoundary = errors.New("lost at a lifecycle boundary")

func (s *boundaryStore) TransitionFirewallAction(id, phase, detail string, at time.Time) (firewall.FirewallAction, error) {
	if phase == s.failTo {
		s.failTo = ""
		return firewall.FirewallAction{}, errBoundary
	}
	return s.DB.TransitionFirewallAction(id, phase, detail, at)
}
func (s *boundaryStore) AcknowledgeFirewallAudit(id string, version uint64) error {
	if s.failAck {
		s.failAck = false
		return errBoundary
	}
	return s.DB.AcknowledgeFirewallAudit(id, version)
}

// boundaryKernel holds one firewall state; Apply installs After, or what
// apply returns, and its observations can fail.
type boundaryKernel struct {
	observedKernel
	apply    func(firewall.FirewallAction) firewall.FirewallState
	failObs  int
	observes int
}

// ObserveFirewallAction fails the failObs-th observation, counting from one.
func (k *boundaryKernel) ObserveFirewallAction(a firewall.FirewallAction) (firewall.ActionObservation, error) {
	k.observes++
	if k.observes == k.failObs {
		return firewall.ActionObservation{}, errBoundary
	}
	return k.observedKernel.ObserveFirewallAction(a)
}
func (k *boundaryKernel) ApplyFirewallAction(a firewall.FirewallAction) error {
	err := k.observedKernel.ApplyFirewallAction(a)
	if k.apply != nil {
		k.state = k.apply(a)
	}
	return err
}

// A batch crosses every lifecycle boundary like a single action: a crash or
// lost write anywhere leaves an outcome recovery proves from the kernel, the
// kernel is written at most once, and every member is charged exactly once.
func TestFirewallBatchLifecycleSurvivesEveryBoundary(t *testing.T) {
	partial := func(a firewall.FirewallAction) firewall.FirewallState {
		s := copyFirewallStateForTest(a.After)
		s.Blocked = s.Blocked[:len(s.Blocked)-1]
		return s
	}
	for _, tc := range []struct {
		name       string
		store      boundaryStore
		kernel     boundaryKernel
		failAudit  bool
		start      func(firewall.FirewallAction) firewall.FirewallState
		wantWrites int
		want       string
	}{
		{name: "clean batch", wantWrites: 1, want: "verified"},
		{name: "lost after admission", store: boundaryStore{failTo: "executing"}, want: "failed"},
		{name: "lost after executing", store: boundaryStore{failTo: "unknown"}, kernel: boundaryKernel{failObs: 1}, want: "failed"},
		{name: "kernel rejects", kernel: boundaryKernel{observedKernel: observedKernel{fail: errBoundary}, apply: func(a firewall.FirewallAction) firewall.FirewallState { return a.Before }}, wantWrites: 1, want: "failed"},
		{name: "lost kernel reply", kernel: boundaryKernel{observedKernel: observedKernel{fail: errBoundary}}, wantWrites: 1, want: "verified"},
		{name: "lost after apply", store: boundaryStore{failTo: "applied"}, wantWrites: 1, want: "verified"},
		{name: "lost after applied", store: boundaryStore{failTo: "unknown"}, kernel: boundaryKernel{failObs: 2}, wantWrites: 1, want: "verified"},
		{name: "lost outcome", store: boundaryStore{failTo: "verified"}, wantWrites: 1, want: "verified"},
		{name: "lost audit", failAudit: true, wantWrites: 1, want: "verified"},
		{name: "lost acknowledgement", store: boundaryStore{failAck: true}, wantWrites: 1, want: "verified"},
		{name: "partial kernel effect", kernel: boundaryKernel{apply: partial}, wantWrites: 1, want: "unknown"},
		{name: "kernel changed before execution", start: partial, want: "unknown"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := openSnapshotDB(t)
			in := batchFixture()
			if _, err := db.ReplaceFirewallState(0, in.Before); err != nil {
				t.Fatal(err)
			}
			s := tc.store
			s.DB = db
			k := tc.kernel
			k.state = in.Before
			if tc.start != nil {
				k.state = tc.start(in)
			}
			var audited []firewall.FirewallAction
			failAudit := tc.failAudit
			l := &firewall.Lifecycle{Store: &s, Audit: func(a firewall.FirewallAction) error {
				audited = append(audited, a)
				if failAudit {
					failAudit = false
					return errBoundary
				}
				return nil
			}}
			first, executeErr := l.Execute(in, &k)
			if tc.want == "verified" && tc.store.failTo == "" && !tc.failAudit && !tc.store.failAck && tc.kernel.fail == nil && executeErr != nil {
				t.Fatalf("clean batch = %#v, %v", first, executeErr)
			}
			if recoverErr := l.Recover(&k); recoverErr != nil && !errors.Is(recoverErr, firewall.ErrActionUnknown) {
				t.Fatalf("recover = %v", recoverErr)
			}
			if auditErr := l.DeliverAudit(); auditErr != nil {
				t.Fatalf("audit retry = %v", auditErr)
			}
			got, err := db.ReadFirewallAction(in.Request.ID)
			if err != nil || got.Phase != tc.want || len(got.Members) != 2 {
				t.Fatalf("outcome = %q (%d members), %v; want %s", got.Phase, len(got.Members), err, tc.want)
			}
			if k.writes != tc.wantWrites {
				t.Fatalf("kernel written %d times, want %d", k.writes, tc.wantWrites)
			}
			if count, budgetErr := db.ReadFirewallScanBudget("2026-01-02T03"); budgetErr != nil || count != 2 {
				t.Fatalf("members charged %d, %v; want 2", count, budgetErr)
			}
			// Every settled outcome publishes a revision; an unknown one does not.
			committed, revision := in.Before, uint64(2)
			switch tc.want {
			case "verified":
				committed = in.After
			case "unknown":
				revision = 1
			}
			assertFirewallSnapshot(t, db, committed, revision)
			pending, err := db.PendingFirewallActions()
			if err != nil || (tc.want == "unknown" && (len(pending) != 1 || pending[0].Request.ID != in.Request.ID)) || (tc.want != "unknown" && len(pending) != 0) {
				t.Fatalf("pending = %#v, %v", pending, err)
			}
			if (tc.failAudit || tc.store.failAck) && len(audited) != 2 {
				t.Fatalf("a lost delivery was not retried: %d deliveries", len(audited))
			}
			if tc.want != "unknown" {
				if len(audited) == 0 || audited[len(audited)-1].AuditVersion != got.AuditVersion || got.AuditAck != got.AuditVersion || len(audited[len(audited)-1].Members) != 2 {
					t.Fatalf("audit = %d deliveries, last %#v; record ack %d of %d", len(audited), audited, got.AuditAck, got.AuditVersion)
				}
			}
			again, _ := l.Execute(in, &k)
			if k.writes != tc.wantWrites || again.Phase != tc.want {
				t.Fatalf("repeated batch = %q after %d writes", again.Phase, k.writes)
			}
		})
	}
}

// An unknown batch stays pending until the kernel proves an outcome.
func TestFirewallBatchUnknownSettlesOnlyOnProof(t *testing.T) {
	db := openSnapshotDB(t)
	in := batchFixture()
	if _, err := db.ReplaceFirewallState(0, in.Before); err != nil {
		t.Fatal(err)
	}
	k := &boundaryKernel{apply: func(a firewall.FirewallAction) firewall.FirewallState {
		s := copyFirewallStateForTest(a.After)
		s.Blocked = s.Blocked[:len(s.Blocked)-1]
		return s
	}}
	k.state = in.Before
	l := &firewall.Lifecycle{Store: db, Audit: func(firewall.FirewallAction) error { return nil }}
	if a, err := l.Execute(in, k); !errors.Is(err, firewall.ErrActionUnknown) || a.Phase != "unknown" {
		t.Fatalf("partial batch = %q, %v", a.Phase, err)
	}
	next := firewallBatchOf(t, db, "batch-two", 4, "member-three", "member-four")
	if _, _, err := db.AdmitFirewallAction(next); !errors.Is(err, firewall.ErrStateConflict) {
		t.Fatalf("admission beside an unknown batch = %v", err)
	}
	k.state = in.After
	if err := l.Recover(k); err != nil {
		t.Fatal(err)
	}
	if a, err := db.ReadFirewallAction(in.Request.ID); err != nil || a.Phase != "verified" {
		t.Fatalf("proven batch = %q, %v", a.Phase, err)
	}
}

// A refused admission leaves no trace: no record, member index or charge.
func TestFirewallBatchAdmissionFailureNeverTouchesKernel(t *testing.T) {
	db := openSnapshotDB(t)
	in := batchFixture()
	if _, err := db.ReplaceFirewallState(0, in.Before); err != nil {
		t.Fatal(err)
	}
	image := batchIndexImage(t, db)
	previous := boltUpdate
	t.Cleanup(func() { boltUpdate = previous })
	boltUpdate = func(*bolt.DB, func(*bolt.Tx) error) error { return errBoundary }
	k := &boundaryKernel{}
	k.state = in.Before
	if _, err := (&firewall.Lifecycle{Store: db}).Execute(in, k); err == nil || k.writes != 0 {
		t.Fatalf("refused admission = %v after %d writes", err, k.writes)
	}
	boltUpdate = previous
	if !bytes.Equal(image, batchIndexImage(t, db)) {
		t.Fatal("refused admission changed journal or member indexes")
	}
	if _, err := db.ReadFirewallAction(in.Request.ID); !errors.Is(err, ErrFirewallActionMissing) {
		t.Fatalf("refused batch left a record: %v", err)
	}
	if count, err := db.ReadFirewallScanBudget("2026-01-02T03"); err != nil || count != 0 {
		t.Fatalf("refused batch charged %d, %v", count, err)
	}
}

type crashBatchStore struct {
	*DB
	after func(string)
}

func (s *crashBatchStore) AdmitFirewallAction(a firewall.FirewallAction) (firewall.FirewallAction, bool, error) {
	got, fresh, err := s.DB.AdmitFirewallAction(a)
	if err == nil && fresh {
		s.after("admit")
	}
	return got, fresh, err
}
func (s *crashBatchStore) TransitionFirewallAction(id, phase, detail string, at time.Time) (firewall.FirewallAction, error) {
	got, err := s.DB.TransitionFirewallAction(id, phase, detail, at)
	if err == nil {
		s.after(phase)
	}
	return got, err
}
func (s *crashBatchStore) AcknowledgeFirewallAudit(id string, version uint64) error {
	err := s.DB.AcknowledgeFirewallAudit(id, version)
	if err == nil {
		s.after("ack")
	}
	return err
}

type crashBatchKernel struct {
	observedKernel
	after    func(string)
	observes int
}

func (k *crashBatchKernel) ObserveFirewallAction(a firewall.FirewallAction) (firewall.ActionObservation, error) {
	got, err := k.observedKernel.ObserveFirewallAction(a)
	k.observes++
	if err == nil {
		step := "observe"
		if k.observes > 1 {
			step = "verify"
		}
		k.after(step)
	}
	return got, err
}
func (k *crashBatchKernel) ApplyFirewallAction(a firewall.FirewallAction) error {
	err := k.observedKernel.ApplyFirewallAction(a)
	if err == nil {
		k.after("apply")
	}
	return err
}

func TestFirewallBatchCrashAfterEachStep(t *testing.T) {
	for _, step := range []string{"admit", "executing", "observe", "apply", "applied", "verify", "verified", "audit", "ack"} {
		t.Run(step, func(t *testing.T) {
			db := openSnapshotDB(t)
			in := batchFixture()
			if _, err := db.ReplaceFirewallState(0, in.Before); err != nil {
				t.Fatal(err)
			}
			sentinel := errors.New("simulated process exit")
			after := func(at string) {
				if at == step {
					panic(sentinel)
				}
			}
			s := &crashBatchStore{DB: db, after: after}
			k := &crashBatchKernel{after: after}
			k.state = in.Before
			deliveries := 0
			audit := func(firewall.FirewallAction) error { deliveries++; after("audit"); return nil }
			crashed := false
			func() {
				defer func() {
					if caught := recover(); caught != nil {
						if caught != sentinel {
							panic(caught)
						}
						crashed = true
					}
				}()
				_, _ = (&firewall.Lifecycle{Store: s, Audit: audit}).Execute(in, k)
			}()
			if !crashed {
				t.Fatalf("did not reach crash checkpoint %s", step)
			}
			path := filepath.Dir(db.bolt.Path())
			if err := db.Close(); err != nil {
				t.Fatal(err)
			}
			reopened, err := Open(path)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = reopened.Close() })
			k.after = func(string) {}
			recovery := &firewall.Lifecycle{Store: reopened, Audit: func(firewall.FirewallAction) error { deliveries++; return nil }}
			if recoveryErr := recovery.Recover(k); recoveryErr != nil {
				t.Fatalf("restart recovery: %v", recoveryErr)
			}
			wantPhase, wantWrites, wantState := "verified", 1, in.After
			if step == "admit" || step == "executing" || step == "observe" {
				wantPhase, wantWrites, wantState = "failed", 0, in.Before
			}
			got, err := reopened.ReadFirewallAction(in.Request.ID)
			if err != nil || got.Phase != wantPhase || got.AuditAck != got.AuditVersion || k.writes != wantWrites {
				t.Fatalf("restart outcome %q, ack %d/%d, writes %d: %v", got.Phase, got.AuditAck, got.AuditVersion, k.writes, err)
			}
			assertFirewallSnapshot(t, reopened, wantState, 2)
			if count, budgetErr := reopened.ReadFirewallScanBudget("2026-01-02T03"); budgetErr != nil || count != 2 {
				t.Fatalf("restart charges = %d, %v", count, budgetErr)
			}
			pending, err := reopened.PendingFirewallActions()
			if err != nil || len(pending) != 0 {
				t.Fatalf("restart pending = %#v, %v", pending, err)
			}
			wantDeliveries := 1
			if step == "audit" {
				wantDeliveries = 2
			}
			if deliveries != wantDeliveries {
				t.Fatalf("restart delivered %d audits, want %d", deliveries, wantDeliveries)
			}
			_, _ = recovery.Execute(in, k)
			if k.writes != wantWrites || deliveries != wantDeliveries {
				t.Fatal("replay after restart wrote again")
			}
		})
	}
}
