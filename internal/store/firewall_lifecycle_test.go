package store

import (
	"errors"
	"reflect"
	"testing"

	"github.com/pidginhost/csm/internal/firewall"
	bolt "go.etcd.io/bbolt"
)

type lifecycleRunner interface {
	Execute(firewall.FirewallAction, firewall.ActionKernel) (firewall.FirewallAction, error)
	Recover(firewall.ActionKernel) error
	DeliverAudit() error
	Undo(firewall.ActionRequest, firewall.ActionKernel) (firewall.FirewallAction, error)
}

type observedKernel struct {
	state       firewall.FirewallState
	writes      int
	afterWrite  func()
	fail        error
	observeFail error
}

func (k *observedKernel) ObserveFirewallAction(a firewall.FirewallAction) (firewall.ActionObservation, error) {
	return firewall.ActionObservation{Before: reflect.DeepEqual(k.state, a.Before), After: reflect.DeepEqual(k.state, a.After)}, k.observeFail
}
func (k *observedKernel) ApplyFirewallAction(a firewall.FirewallAction) error {
	k.writes++
	k.state = a.After
	if k.afterWrite != nil {
		k.afterWrite()
	}
	return k.fail
}

func lifecycleFor(t *testing.T, db *DB, audit func(firewall.FirewallAction) error) lifecycleRunner {
	t.Helper()
	l := &firewall.Lifecycle{Store: actionStore(t, db), Audit: audit}
	r, ok := any(l).(lifecycleRunner)
	if !ok {
		t.Fatal("firewall lifecycle has no execution/recovery boundary")
	}
	return r
}

func TestFirewallLifecycleAdmissionFailureNeverTouchesKernel(t *testing.T) {
	db := openSnapshotDB(t)
	l := lifecycleFor(t, db, func(firewall.FirewallAction) error { return nil })
	a := admissionFixture()
	if _, err := db.ReplaceFirewallState(0, a.Before); err != nil {
		t.Fatal(err)
	}
	previous := boltUpdate
	t.Cleanup(func() { boltUpdate = previous })
	boltUpdate = func(*bolt.DB, func(*bolt.Tx) error) error { return errors.New("storage unavailable") }
	k := &observedKernel{state: a.Before}
	if _, err := l.Execute(a, k); err == nil {
		t.Fatal("admission failure reported success")
	}
	if k.writes != 0 {
		t.Fatal("kernel touched before durable admission")
	}
	assertFirewallSnapshot(t, db, a.Before, 1)
}

func TestFirewallLifecycleLostKernelAcknowledgementIsVerified(t *testing.T) {
	db := openSnapshotDB(t)
	var audited []firewall.FirewallAction
	l := lifecycleFor(t, db, func(a firewall.FirewallAction) error { audited = append(audited, a); return nil })
	a := admissionFixture()
	if _, err := db.ReplaceFirewallState(0, a.Before); err != nil {
		t.Fatal(err)
	}
	k := &observedKernel{state: a.Before, fail: errors.New("lost kernel reply")}
	result, err := l.Execute(a, k)
	if err != nil || result.Phase != "verified" {
		t.Fatalf("result = %#v, %v", result, err)
	}
	assertFirewallSnapshot(t, db, a.After, 2)
	if len(audited) != 1 || audited[0].Request.ID != a.Request.ID {
		t.Fatalf("audit = %#v", audited)
	}
	if _, err := l.Execute(a, k); err != nil {
		t.Fatal(err)
	}
	if k.writes != 1 {
		t.Fatal("duplicate replayed kernel mutation")
	}
}

func TestFirewallLifecycleRecoveryNeverReplays(t *testing.T) {
	for _, point := range []string{"planned", "executing", "applied", "unknown"} {
		for _, changed := range []bool{false, true} {
			t.Run(point+map[bool]string{false: "-before", true: "-after"}[changed], func(t *testing.T) {
				db := openSnapshotDB(t)
				l := lifecycleFor(t, db, func(firewall.FirewallAction) error { return nil })
				a := admissionFixture()
				if _, err := db.ReplaceFirewallState(0, a.Before); err != nil {
					t.Fatal(err)
				}
				if _, _, err := db.AdmitFirewallAction(a); err != nil {
					t.Fatal(err)
				}
				if point != "planned" {
					if _, err := db.TransitionFirewallAction(a.Request.ID, "executing", "", a.CreatedAt); err != nil {
						t.Fatal(err)
					}
				}
				if point == "applied" || point == "unknown" {
					if _, err := db.TransitionFirewallAction(a.Request.ID, point, "", a.CreatedAt); err != nil {
						t.Fatal(err)
					}
				}
				k := &observedKernel{state: a.Before}
				want, revision := a.Before, uint64(2)
				if changed {
					k.state, want = a.After, a.After
				}
				if err := l.Recover(k); err != nil {
					t.Fatal(err)
				}
				if k.writes != 0 {
					t.Fatal("recovery replayed mutation")
				}
				assertFirewallSnapshot(t, db, want, revision)
			})
		}
	}
}

func TestFirewallLifecycleUnknownBlocksConflictsAndRetriesAudit(t *testing.T) {
	db := openSnapshotDB(t)
	auditErr := errors.New("audit storage unavailable")
	var ids []string
	l := lifecycleFor(t, db, func(a firewall.FirewallAction) error { ids = append(ids, a.Request.ID); return auditErr })
	a := admissionFixture()
	if _, err := db.ReplaceFirewallState(0, a.Before); err != nil {
		t.Fatal(err)
	}
	k := &observedKernel{state: a.Before}
	k.afterWrite = func() { k.observeFail = errors.New("kernel inspection unavailable") }
	if _, err := l.Execute(a, k); !errors.Is(err, firewall.ErrActionUnknown) {
		t.Fatalf("unknown = %v", err)
	}
	other := a
	other.Request.ID = "conflict"
	if _, err := l.Execute(other, k); err == nil {
		t.Fatal("conflicting action accepted")
	}
	if k.writes != 1 {
		t.Fatal("uncertain action was replayed")
	}
	k.observeFail = nil
	if err := l.Recover(k); err == nil {
		t.Fatal("audit outage hidden")
	}
	pending, err := db.FirewallAuditPending()
	if err != nil || len(pending) != 2 {
		t.Fatalf("audit work = %#v, %v", pending, err)
	}
	auditErr = nil
	if err := l.DeliverAudit(); err != nil {
		t.Fatal(err)
	}
	for _, id := range ids {
		if id != a.Request.ID {
			t.Fatalf("retry identity = %q", id)
		}
	}
}

func TestFirewallLifecycleOutcomeFailureRetainsRecovery(t *testing.T) {
	db := openSnapshotDB(t)
	l := lifecycleFor(t, db, func(firewall.FirewallAction) error { return nil })
	a := admissionFixture()
	if _, err := db.ReplaceFirewallState(0, a.Before); err != nil {
		t.Fatal(err)
	}
	previous := boltUpdate
	t.Cleanup(func() { boltUpdate = previous })
	k := &observedKernel{state: a.Before, afterWrite: func() {
		boltUpdate = func(*bolt.DB, func(*bolt.Tx) error) error { return errors.New("outcome storage unavailable") }
	}}
	if _, err := l.Execute(a, k); !errors.Is(err, firewall.ErrActionUnknown) {
		t.Fatalf("outcome failure = %v", err)
	}
	assertFirewallSnapshot(t, db, a.Before, 1)
	boltUpdate = previous
	if err := l.Recover(k); err != nil {
		t.Fatal(err)
	}
	assertFirewallSnapshot(t, db, a.After, 2)
	if k.writes != 1 {
		t.Fatal("recovery replayed successful mutation")
	}
}

func TestFirewallLifecycleUndoChecksIdentityAndLinksAction(t *testing.T) {
	db := openSnapshotDB(t)
	l := lifecycleFor(t, db, func(firewall.FirewallAction) error { return nil })
	a := admissionFixture()
	if _, err := db.ReplaceFirewallState(0, a.Before); err != nil {
		t.Fatal(err)
	}
	k := &observedKernel{state: a.Before}
	if _, err := l.Execute(a, k); err != nil {
		t.Fatal(err)
	}
	req := firewall.ActionRequest{ID: "undo-request", Operation: "undo", Actor: "cli", Source: "cli", UndoOf: a.Request.ID}
	k.state = firewall.FirewallState{}
	if _, err := l.Undo(req, k); err == nil {
		t.Fatal("undo accepted changed kernel target")
	}
	k.state = a.After
	result, err := l.Undo(req, k)
	if err != nil || result.Request.UndoOf != a.Request.ID || result.Phase != "verified" {
		t.Fatalf("undo = %#v, %v", result, err)
	}
	assertFirewallSnapshot(t, db, a.Before, 3)
	if !result.After.Blocked[0].ExpiresAt.Equal(a.Before.Blocked[0].ExpiresAt) {
		t.Fatal("undo renewed original expiry")
	}
}
