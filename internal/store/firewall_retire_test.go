package store

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/firewall"
	bolt "go.etcd.io/bbolt"
)

// unknownBatch admits a batch planned two hours ago with one-hour members
// and leaves it unknown; acknowledged delivers that outcome's audit.
func unknownBatch(t *testing.T, db *DB, acknowledged bool) firewall.FirewallAction {
	t.Helper()
	planned := time.Now().UTC().Round(0).Add(-2 * time.Hour)
	before := firewall.FirewallState{Blocked: []firewall.BlockedEntry{{IP: "192.0.2.1", Reason: "permanent", BlockedAt: planned.Add(-time.Hour)}}}
	if _, err := db.ReplaceFirewallState(0, before); err != nil {
		t.Fatal(err)
	}
	a := firewall.FirewallAction{
		Request: firewall.ActionRequest{ID: "batch-unknown", Operation: "block", Actor: "auto", Source: "scan", Automatic: true},
		Before:  before, After: copyFirewallStateForTest(before), Revision: 1, CreatedAt: planned,
	}
	for i, id := range []string{"member-1", "member-2"} {
		m := firewall.ActionMember{
			Request: firewall.ActionRequest{ID: id, Operation: "block", Target: fmt.Sprintf("203.0.113.%d", 20+i), Reason: "brute force", Actor: "auto", Source: "scan", Automatic: true, TTL: time.Hour},
			Budget:  &firewall.ScanAdmission{Window: planned.Format(firewallScanWindowLayout), Limit: 4},
		}
		a.Members = append(a.Members, m)
		a.After.Blocked = append(a.After.Blocked, batchMemberRow(a, m))
	}
	if _, fresh, err := db.AdmitFirewallAction(a); err != nil || !fresh {
		t.Fatalf("admit = %v, %v", fresh, err)
	}
	if _, err := db.TransitionFirewallAction(a.Request.ID, "executing", "", planned); err != nil {
		t.Fatal(err)
	}
	u, err := db.TransitionFirewallAction(a.Request.ID, "unknown", "lost kernel reply", planned.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if acknowledged {
		if err := db.AcknowledgeFirewallAudit(u.Request.ID, u.AuditVersion); err != nil {
			t.Fatal(err)
		}
	}
	return u
}

// Retirement commits the rows Before and After agree on as the next
// revision, frees the pending interlock and records the event, keeping the
// unknown outcome and the charges.
func TestFirewallRetireCommitsTheAgreedState(t *testing.T) {
	db := openSnapshotDB(t)
	a := unknownBatch(t, db, true)
	at := time.Now().UTC().Round(0)
	retired, err := db.RetireFirewallAction(a.Request.ID, at)
	if err != nil || !retired.Retired || retired.Phase != "unknown" || retired.AuditVersion != a.AuditVersion+1 || !retired.UpdatedAt.Equal(at) || retired.Detail != a.Detail {
		t.Fatalf("retired = %#v, %v", retired, err)
	}
	assertFirewallSnapshot(t, db, a.Before, 2)
	if pending, pendingErr := db.PendingFirewallActions(); pendingErr != nil || len(pending) != 0 {
		t.Fatalf("pending after retirement = %d, %v", len(pending), pendingErr)
	}
	audit, err := db.FirewallAuditPending()
	if err != nil || len(audit) != 1 || !audit[0].Retired || audit[0].AuditVersion != retired.AuditVersion {
		t.Fatalf("retirement audit = %#v, %v", audit, err)
	}
	if count, err := db.ReadFirewallScanBudget(a.Members[0].Budget.Window); err != nil || count != 2 {
		t.Fatalf("charges after retirement = %d, %v", count, err)
	}
	if again, err := db.RetireFirewallAction(a.Request.ID, at.Add(time.Minute)); err != nil || again.AuditVersion != retired.AuditVersion || !again.UpdatedAt.Equal(at) {
		t.Fatalf("second retirement = %#v, %v", again, err)
	}
	assertFirewallSnapshot(t, db, a.Before, 2)
	for _, phase := range []string{"verified", "unknown"} {
		if _, err := db.TransitionFirewallAction(a.Request.ID, phase, "operator", at); !errors.Is(err, firewall.ErrStateConflict) {
			t.Fatalf("%s transition of a retired action = %v", phase, err)
		}
	}
	next := admissionFixture()
	next.Request.ID, next.Before, next.After, next.Revision, next.Budget = "after-retirement", a.Before, firewall.FirewallState{}, 2, nil
	if _, fresh, err := db.AdmitFirewallAction(next); err != nil || !fresh {
		t.Fatalf("admission after retirement = %v, %v", fresh, err)
	}
}

// An action retires only once its unknown outcome reached the audit trail
// and every timed effect has expired; anything else changes nothing.
func TestFirewallRetireRefusesUntilEveryEffectExpired(t *testing.T) {
	now := time.Now().UTC().Round(0)
	for name, tc := range map[string]struct {
		setup func(*testing.T, *DB) firewall.FirewallAction
		at    time.Time
	}{
		"audit undelivered": {func(t *testing.T, db *DB) firewall.FirewallAction { return unknownBatch(t, db, false) }, now},
		"member still live": {func(t *testing.T, db *DB) firewall.FirewallAction { return unknownBatch(t, db, true) }, now.Add(-90 * time.Minute)},
		"no instant":        {func(t *testing.T, db *DB) firewall.FirewallAction { return unknownBatch(t, db, true) }, time.Time{}},
		"a permanent block": {func(t *testing.T, db *DB) firewall.FirewallAction {
			if _, err := db.ReplaceFirewallState(0, firewall.FirewallState{}); err != nil {
				t.Fatal(err)
			}
			a := firewall.FirewallAction{Request: firewall.ActionRequest{ID: "permanent", Operation: "block", Target: "203.0.113.40", Actor: "cli", Source: "cli"}, Revision: 1, CreatedAt: now.Add(-time.Hour)}
			a.After.Blocked = []firewall.BlockedEntry{{IP: "203.0.113.40", Reason: "operator", BlockedAt: a.CreatedAt}}
			if _, _, err := db.AdmitFirewallAction(a); err != nil {
				t.Fatal(err)
			}
			u, err := db.TransitionFirewallAction(a.Request.ID, "unknown", "lost kernel reply", a.CreatedAt)
			if err != nil {
				t.Fatal(err)
			}
			if err := db.AcknowledgeFirewallAudit(u.Request.ID, u.AuditVersion); err != nil {
				t.Fatal(err)
			}
			return u
		}, now},
	} {
		t.Run(name, func(t *testing.T) {
			db := openSnapshotDB(t)
			a := tc.setup(t, db)
			image := batchIndexImage(t, db)
			if _, err := db.RetireFirewallAction(a.Request.ID, tc.at); !errors.Is(err, firewall.ErrStateConflict) {
				t.Fatalf("retirement = %v", err)
			}
			if !reflect.DeepEqual(batchIndexImage(t, db), image) {
				t.Fatal("refused retirement changed the journal")
			}
		})
	}
	t.Run("a verified action", func(t *testing.T) {
		db := openSnapshotDB(t)
		a := unknownBatch(t, db, true)
		verified, err := db.TransitionFirewallAction(a.Request.ID, "verified", "", now)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := db.RetireFirewallAction(verified.Request.ID, now); !errors.Is(err, firewall.ErrStateConflict) {
			t.Fatalf("retirement of a verified action = %v", err)
		}
	})
}

// Only an unknown outcome can carry the retired mark, and the pending index
// never names a retired action: either is damage.
func TestFirewallRetiredMarkIsValidated(t *testing.T) {
	db := openSnapshotDB(t)
	a := unknownBatch(t, db, true)
	retired, err := db.RetireFirewallAction(a.Request.ID, time.Now().UTC().Round(0))
	if err != nil {
		t.Fatal(err)
	}
	marked := retired
	marked.Phase = "verified"
	raw, err := encodeFirewallActionRecord(marked)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeFirewallAction(raw); !errors.Is(err, firewall.ErrStateCorrupt) {
		t.Fatalf("retired verified action read as %v", err)
	}
	if err := db.bolt.Update(func(tx *bolt.Tx) error {
		index, err := readFirewallJournalIndex(tx)
		if err != nil {
			return err
		}
		index.PendingID = retired.Request.ID
		return writeFirewallJournalIndex(tx, index)
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.PendingFirewallActions(); !errors.Is(err, firewall.ErrStateCorrupt) {
		t.Fatalf("pending index naming a retired action = %v", err)
	}

	db = openSnapshotDB(t)
	a = unknownBatch(t, db, true)
	if err := db.bolt.Update(func(tx *bolt.Tx) error {
		index, err := readFirewallJournalIndex(tx)
		if err != nil {
			return err
		}
		index.PendingID = ""
		return writeFirewallJournalIndex(tx, index)
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.RetireFirewallAction(a.Request.ID, time.Now().UTC().Round(0)); !errors.Is(err, firewall.ErrStateCorrupt) {
		t.Fatalf("retirement of an unknown action the index does not name = %v", err)
	}
}

// The records this plan adds, exported for the old-reader probe: a single
// block with its victim, and a retired batch. The new reader reads both.
func TestFirewallRetiredCompatibilityFixture(t *testing.T) {
	dir := os.Getenv("CSM_TEST_BATCH_COMPAT_DIR")
	if dir == "" {
		dir = t.TempDir()
	}
	for _, name := range []string{"victim", "retired"} {
		t.Run(name, func(t *testing.T) {
			db := openSnapshotDB(t)
			in := victimFixture()
			if name == "retired" {
				in = batchFixture()
			}
			a := admitFixture(t, db, in)
			if name == "retired" {
				u, err := db.TransitionFirewallAction(in.Request.ID, "unknown", "fixture", in.CreatedAt)
				if err != nil {
					t.Fatal(err)
				}
				if err = db.AcknowledgeFirewallAudit(u.Request.ID, u.AuditVersion); err != nil {
					t.Fatal(err)
				}
				if a, err = db.RetireFirewallAction(in.Request.ID, in.CreatedAt.Add(2*time.Hour)); err != nil {
					t.Fatal(err)
				}
			}
			var raw []byte
			if err := db.bolt.View(func(tx *bolt.Tx) error {
				raw = bytes.Clone(tx.Bucket([]byte(firewallActionsBucket)).Get([]byte(a.Request.ID)))
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			decoded, err := decodeFirewallAction(raw)
			if err != nil || !decoded.SameManifest(a) || decoded.Phase != a.Phase || decoded.Retired != (name == "retired") {
				t.Fatalf("fixture round trip = %#v, %v", decoded, err)
			}
			if err := os.WriteFile(filepath.Join(dir, name+".json"), raw, 0600); err != nil {
				t.Fatal(err)
			}
			if name == "retired" {
				if err := db.bolt.View(func(tx *bolt.Tx) error { return tx.CopyFile(filepath.Join(dir, "retired.db"), 0600) }); err != nil {
					t.Fatal(err)
				}
			}
			old, readErr := os.ReadFile(filepath.Join(dir, name+"-old.json"))
			if readErr == nil {
				fromOld, err := decodeFirewallAction(old)
				if err != nil || !fromOld.SameManifest(a) || fromOld.Phase != a.Phase || fromOld.Retired || (name == "victim" && !bytes.Equal(old, raw)) {
					t.Fatalf("new reader of old %s record: %#v %v", name, fromOld, err)
				}
			} else if !os.IsNotExist(readErr) {
				t.Fatal(readErr)
			}
			if name == "retired" {
				oldDB, readErr := os.ReadFile(filepath.Join(dir, "retired-acked.db"))
				if readErr == nil {
					dbDir := t.TempDir()
					if err := os.WriteFile(filepath.Join(dbDir, "csm.db"), oldDB, 0600); err != nil {
						t.Fatal(err)
					}
					reopened, err := Open(dbDir)
					if err != nil {
						t.Fatal(err)
					}
					defer func() {
						if closeErr := reopened.Close(); closeErr != nil {
							t.Error(closeErr)
						}
					}()
					got, err := reopened.ReadFirewallAction(a.Request.ID)
					if err != nil || got.Retired || got.Phase != "unknown" {
						t.Fatalf("old ack read: %#v %v", got, err)
					}
					if pending, err := reopened.PendingFirewallActions(); err != nil || len(pending) != 0 {
						t.Fatalf("old ack pending: %#v %v", pending, err)
					}
					if _, err := reopened.TransitionFirewallAction(a.Request.ID, "failed", "operator", a.UpdatedAt); !errors.Is(err, firewall.ErrStateCorrupt) {
						t.Fatalf("old ack transition: %v", err)
					}
					assertFirewallSnapshot(t, reopened, a.Before, a.Revision+1)
				} else if !os.IsNotExist(readErr) {
					t.Fatal(readErr)
				}
			}
		})
	}
}

// retiringKernel never proves an outcome; it proves a retirement when told.
type retiringKernel struct {
	observedKernel
	proven   bool
	at       time.Time
	calls    int
	proofErr error
}

func (k *retiringKernel) ProveFirewallRetirement(firewall.FirewallAction) (time.Time, bool, error) {
	k.calls++
	return k.at, k.proven, k.proofErr
}

// Recovery retires an unknown action once its outcome audit is delivered and
// the kernel proves the retired state; until then the action stays pending.
func TestFirewallRecoverRetiresAnExpiredUnknownAction(t *testing.T) {
	neither := firewall.FirewallState{Blocked: []firewall.BlockedEntry{{IP: "198.51.100.99", Reason: "unrelated"}}}
	t.Run("proven", func(t *testing.T) {
		db := openSnapshotDB(t)
		var audited []firewall.FirewallAction
		l := lifecycleFor(t, db, func(a firewall.FirewallAction) error { audited = append(audited, a); return nil })
		a := unknownBatch(t, db, false)
		k := &retiringKernel{observedKernel: observedKernel{state: neither}, proven: true, at: time.Now().UTC().Round(0)}
		if err := l.Recover(k); err != nil {
			t.Fatalf("recovery = %v", err)
		}
		if k.calls != 1 || k.writes != 0 {
			t.Fatalf("prover calls %d, kernel writes %d", k.calls, k.writes)
		}
		if len(audited) == 0 || !audited[len(audited)-1].Retired {
			t.Fatalf("audit did not deliver the retirement: %#v", audited)
		}
		if pending, err := db.FirewallAuditPending(); err != nil || len(pending) != 0 {
			t.Fatalf("undelivered audit = %d, %v", len(pending), err)
		}
		assertFirewallSnapshot(t, db, a.Before, 2)
	})
	for name, k := range map[string]firewall.ActionKernel{
		"not proven": &retiringKernel{observedKernel: observedKernel{state: neither}, at: time.Now().UTC()},
		"no prover":  &observedKernel{state: neither},
	} {
		t.Run(name, func(t *testing.T) {
			db := openSnapshotDB(t)
			l := lifecycleFor(t, db, func(firewall.FirewallAction) error { return nil })
			unknownBatch(t, db, false)
			if err := l.Recover(k); !errors.Is(err, firewall.ErrActionUnknown) {
				t.Fatalf("recovery = %v", err)
			}
			if pending, err := db.PendingFirewallActions(); err != nil || len(pending) != 1 || pending[0].Retired {
				t.Fatalf("pending = %#v, %v", pending, err)
			}
		})
	}
	t.Run("audit undelivered", func(t *testing.T) {
		db := openSnapshotDB(t)
		sinkDown := errors.New("audit sink down")
		l := lifecycleFor(t, db, func(firewall.FirewallAction) error { return sinkDown })
		unknownBatch(t, db, false)
		k := &retiringKernel{observedKernel: observedKernel{state: neither}, proven: true, at: time.Now().UTC()}
		if err := l.Recover(k); !errors.Is(err, sinkDown) {
			t.Fatalf("recovery = %v", err)
		}
		if k.calls != 0 {
			t.Fatal("retirement attempted before the outcome was audited")
		}
	})
}

// A retired action is settled: an operator cannot resolve it, and a retry of
// its ID reports the unknown outcome without touching the kernel or journal.
func TestFirewallRetiredActionIsSettled(t *testing.T) {
	db := openSnapshotDB(t)
	l := lifecycleFor(t, db, func(firewall.FirewallAction) error { return nil })
	a := unknownBatch(t, db, true)
	retired, err := db.RetireFirewallAction(a.Request.ID, time.Now().UTC().Round(0))
	if err != nil {
		t.Fatal(err)
	}
	k := &countingKernel{observedKernel: observedKernel{state: a.Before}}
	resolver, ok := any(l).(interface {
		Resolve(string, string, string, firewall.ActionKernel) (firewall.FirewallAction, error)
	})
	if !ok {
		t.Fatal("lifecycle has no resolve boundary")
	}
	if _, resolveErr := resolver.Resolve(a.Request.ID, "failed", "operator", k); resolveErr == nil {
		t.Fatal("a retired action was resolved")
	}
	result, err := l.Execute(retired, k)
	if k.observed != 0 {
		t.Fatalf("a settled action read the kernel %d times", k.observed)
	}
	if !errors.Is(err, firewall.ErrActionUnknown) || k.writes != 0 || result.AuditVersion != retired.AuditVersion {
		t.Fatalf("retry of a retired action = %d writes, version %d, %v", k.writes, result.AuditVersion, err)
	}
}

// countingKernel counts observations.
type countingKernel struct {
	observedKernel
	observed int
}

func (k *countingKernel) ObserveFirewallAction(a firewall.FirewallAction) (firewall.ActionObservation, error) {
	k.observed++
	return k.observedKernel.ObserveFirewallAction(a)
}
