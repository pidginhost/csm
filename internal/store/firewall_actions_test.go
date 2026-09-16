package store

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/firewall"
	bolt "go.etcd.io/bbolt"
)

func actionStore(t *testing.T, db *DB) firewall.ActionStore {
	t.Helper()
	s, ok := any(db).(firewall.ActionStore)
	if !ok {
		t.Fatal("store lacks atomic firewall action admission")
	}
	return s
}

func admissionFixture() firewall.FirewallAction {
	before := completeFirewallState()
	after := completeFirewallState()
	after.Blocked = after.Blocked[1:]
	return firewall.FirewallAction{
		Request: firewall.ActionRequest{ID: "request-one", Operation: "unblock", Target: "203.0.113.90", Actor: "cli", Source: "scan"},
		Before:  before, After: after, Revision: 1,
		CreatedAt: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
		Budget:    &firewall.ScanAdmission{Window: "2026-01-02T03", Limit: 1},
	}
}

func TestFirewallActionAdmissionKeepsCommittedState(t *testing.T) {
	db := openSnapshotDB(t)
	s := actionStore(t, db)
	in := admissionFixture()
	if _, err := s.ReplaceFirewallState(0, in.Before); err != nil {
		t.Fatal(err)
	}
	a, fresh, err := s.AdmitFirewallAction(in)
	if err != nil || !fresh || a.Phase != "planned" {
		t.Fatalf("admit = %#v, %v, %v", a, fresh, err)
	}
	assertFirewallSnapshot(t, s, in.Before, 1)
	count, err := s.ReadFirewallScanBudget(in.Budget.Window)
	if err != nil || count != 1 {
		t.Fatalf("budget = %d, %v", count, err)
	}
	in.After.Blocked[0].Reason = "caller edit"
	stored, err := s.ReadFirewallAction(in.Request.ID)
	if err != nil || stored.After.Blocked[0].Reason != "permanent" {
		t.Fatalf("stored = %#v, %v", stored, err)
	}
	if _, err := s.ReplaceFirewallState(1, in.After); err == nil {
		t.Fatal("replacement bypassed pending recovery")
	}
	other := admissionFixture()
	other.Request.ID = "another-request"
	other.Budget = nil
	if _, _, err := s.AdmitFirewallAction(other); err == nil {
		t.Fatal("conflicting admission accepted")
	}
}

func TestFirewallActionAdmissionRollbackKeepsBudget(t *testing.T) {
	db := openSnapshotDB(t)
	s := actionStore(t, db)
	in := admissionFixture()
	if _, err := s.ReplaceFirewallState(0, in.Before); err != nil {
		t.Fatal(err)
	}
	previous := boltUpdate
	t.Cleanup(func() { boltUpdate = previous })
	failure := errors.New("forced rollback")
	boltUpdate = func(db *bolt.DB, fn func(*bolt.Tx) error) error {
		return db.Update(func(tx *bolt.Tx) error {
			if err := fn(tx); err != nil {
				return err
			}
			return failure
		})
	}
	if _, _, err := s.AdmitFirewallAction(in); !errors.Is(err, failure) {
		t.Fatalf("admit error = %v", err)
	}
	assertFirewallSnapshot(t, s, in.Before, 1)
	count, err := s.ReadFirewallScanBudget(in.Budget.Window)
	if err != nil || count != 0 {
		t.Fatalf("budget = %d, %v", count, err)
	}
	pending, err := s.PendingFirewallActions()
	if err != nil || len(pending) != 0 {
		t.Fatalf("pending = %#v, %v", pending, err)
	}
}

func TestFirewallActionRetryKeepsExpiryAndReservation(t *testing.T) {
	db := openSnapshotDB(t)
	s := actionStore(t, db)
	in := admissionFixture()
	if _, err := s.ReplaceFirewallState(0, in.Before); err != nil {
		t.Fatal(err)
	}
	original, _, err := s.AdmitFirewallAction(in)
	if err != nil {
		t.Fatal(err)
	}
	in.After.Blocked[0].ExpiresAt = in.CreatedAt.Add(time.Hour)
	in.Revision++
	retry, fresh, err := s.AdmitFirewallAction(in)
	if err != nil || fresh || !reflect.DeepEqual(original, retry) {
		t.Fatalf("retry = %#v, %v, %v", retry, fresh, err)
	}
	in.Request.Reason = "different request under same ID"
	if _, _, retryErr := s.AdmitFirewallAction(in); retryErr == nil {
		t.Fatal("reused ID changed request")
	}
	count, err := s.ReadFirewallScanBudget(in.Budget.Window)
	if err != nil || count != 1 {
		t.Fatalf("budget = %d, %v", count, err)
	}
}

func TestFirewallActionOutcomeAndAuditCommitTogether(t *testing.T) {
	db := openSnapshotDB(t)
	s := actionStore(t, db)
	in := admissionFixture()
	if _, err := s.ReplaceFirewallState(0, in.Before); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.AdmitFirewallAction(in); err != nil {
		t.Fatal(err)
	}
	for _, phase := range []string{"executing", "applied", "unknown"} {
		if _, err := s.TransitionFirewallAction(in.Request.ID, phase, "", in.CreatedAt); err != nil {
			t.Fatal(err)
		}
		assertFirewallSnapshot(t, s, in.Before, 1)
	}
	previous := boltUpdate
	t.Cleanup(func() { boltUpdate = previous })
	failure := errors.New("outcome commit refused")
	boltUpdate = func(db *bolt.DB, fn func(*bolt.Tx) error) error {
		return db.Update(func(tx *bolt.Tx) error {
			if err := fn(tx); err != nil {
				return err
			}
			return failure
		})
	}
	if _, err := s.TransitionFirewallAction(in.Request.ID, "verified", "", in.CreatedAt); !errors.Is(err, failure) {
		t.Fatalf("resolve = %v", err)
	}
	assertFirewallSnapshot(t, s, in.Before, 1)
	a, err := s.ReadFirewallAction(in.Request.ID)
	if err != nil || a.Phase != "unknown" {
		t.Fatalf("outcome = %#v, %v", a, err)
	}
	boltUpdate = previous
	a, err = s.TransitionFirewallAction(in.Request.ID, "verified", "", in.CreatedAt)
	if err != nil {
		t.Fatal(err)
	}
	assertFirewallSnapshot(t, s, in.After, 2)
	pending, err := s.PendingFirewallActions()
	if err != nil || len(pending) != 0 {
		t.Fatalf("pending = %#v, %v", pending, err)
	}
	audits, err := s.FirewallAuditPending()
	if err != nil || len(audits) != 2 || audits[0].Phase != "unknown" || audits[1].Phase != "verified" || audits[0].Request.ID != in.Request.ID {
		t.Fatalf("audit = %#v, %v", audits, err)
	}
	if ackErr := s.AcknowledgeFirewallAudit(in.Request.ID, a.AuditVersion+1); ackErr == nil {
		t.Fatal("nonexistent audit acknowledgement accepted")
	}
	if ackErr := s.AcknowledgeFirewallAudit(in.Request.ID, audits[0].AuditVersion); ackErr != nil {
		t.Fatal(ackErr)
	}
	if ackErr := s.AcknowledgeFirewallAudit(in.Request.ID, a.AuditVersion); ackErr != nil {
		t.Fatal(ackErr)
	}
	audits, err = s.FirewallAuditPending()
	if err != nil || len(audits) != 0 {
		t.Fatalf("acknowledged audit = %#v, %v", audits, err)
	}
	if _, err := s.TransitionFirewallAction(in.Request.ID, "executing", "", in.CreatedAt); err == nil {
		t.Fatal("terminal action rearmed")
	}
}

func TestFirewallActionBudgetExemptionsAndFailure(t *testing.T) {
	db := openSnapshotDB(t)
	s := actionStore(t, db)
	in := admissionFixture()
	if _, err := s.ReplaceFirewallState(0, in.Before); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.AdmitFirewallAction(in); err != nil {
		t.Fatal(err)
	}
	if _, err := s.TransitionFirewallAction(in.Request.ID, "failed", "kernel retains before state", in.CreatedAt); err != nil {
		t.Fatal(err)
	}
	assertFirewallSnapshot(t, s, in.Before, 2)
	in.Request.ID = "second-scan"
	in.Revision = 2
	if _, _, err := s.AdmitFirewallAction(in); err == nil {
		t.Fatal("scan budget exceeded")
	}
	in.Request.Source = "incident"
	if _, _, err := s.AdmitFirewallAction(in); err == nil {
		t.Fatal("non-scan request charged to scan budget")
	}
	in.Budget = nil
	if _, _, err := s.AdmitFirewallAction(in); err != nil {
		t.Fatal(err)
	}
	count, err := s.ReadFirewallScanBudget("2026-01-02T03")
	if err != nil || count != 1 {
		t.Fatalf("budget = %d, %v", count, err)
	}
}

func TestFirewallActionRejectsLossyEvidence(t *testing.T) {
	for _, change := range []struct {
		name string
		edit func(*firewall.FirewallAction)
	}{
		{"actor text", func(a *firewall.FirewallAction) { a.Request.Actor = string([]byte{0xff}) }},
		{"identity text", func(a *firewall.FirewallAction) { a.Request.ID = string([]byte{0xff}) }},
		{"time offset", func(a *firewall.FirewallAction) { a.CreatedAt = a.CreatedAt.In(time.FixedZone("seconds", 1)) }},
		{"budget window", func(a *firewall.FirewallAction) { a.Budget.Window = "invalid" }},
	} {
		t.Run(change.name, func(t *testing.T) {
			db := openSnapshotDB(t)
			s := actionStore(t, db)
			in := admissionFixture()
			if _, err := s.ReplaceFirewallState(0, in.Before); err != nil {
				t.Fatal(err)
			}
			change.edit(&in)
			if _, _, err := s.AdmitFirewallAction(in); err == nil {
				t.Fatal("lossy or invalid action accepted")
			}
			pending, err := s.PendingFirewallActions()
			if err != nil || len(pending) != 0 {
				t.Fatalf("refused admission left state: %#v, %v", pending, err)
			}
		})
	}
}

func TestFirewallActionCorruptionNeverReturnsPartialRecovery(t *testing.T) {
	db := openSnapshotDB(t)
	s := actionStore(t, db)
	in := admissionFixture()
	if _, err := s.ReplaceFirewallState(0, in.Before); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.AdmitFirewallAction(in); err != nil {
		t.Fatal(err)
	}
	if err := db.bolt.Update(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte("fw:actions")).Put([]byte(in.Request.ID), []byte(`{"phase":"executing"}`))
	}); err != nil {
		t.Fatal(err)
	}
	if got, err := s.PendingFirewallActions(); !errors.Is(err, firewall.ErrStateCorrupt) || got != nil {
		t.Fatalf("partial recovery = %#v, %v", got, err)
	}
}

func TestFirewallActionCorruptBudgetRefusesAdmission(t *testing.T) {
	db := openSnapshotDB(t)
	s := actionStore(t, db)
	in := admissionFixture()
	if _, err := s.ReplaceFirewallState(0, in.Before); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.AdmitFirewallAction(in); err != nil {
		t.Fatal(err)
	}
	if _, err := s.TransitionFirewallAction(in.Request.ID, "failed", "not applied", in.CreatedAt); err != nil {
		t.Fatal(err)
	}
	in.Request.ID = "next-request"
	in.Revision = 2
	if err := db.bolt.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists([]byte("fw:scan_budget"))
		if err != nil {
			return err
		}
		if deleteErr := b.Delete([]byte(in.Budget.Window)); deleteErr != nil {
			return deleteErr
		}
		_, err = b.CreateBucket([]byte(in.Budget.Window))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.AdmitFirewallAction(in); !errors.Is(err, firewall.ErrStateCorrupt) {
		t.Fatalf("nested budget = %v", err)
	}
}

func TestFirewallActionExecutingRefusesDamagedBase(t *testing.T) {
	db := openSnapshotDB(t)
	s := actionStore(t, db)
	in := admissionFixture()
	if _, err := s.ReplaceFirewallState(0, in.Before); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.AdmitFirewallAction(in); err != nil {
		t.Fatal(err)
	}
	if err := db.bolt.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("fw:blocked"))
		return b.Put([]byte("unexpected"), []byte(`{}`))
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.TransitionFirewallAction(in.Request.ID, "executing", "", in.CreatedAt); !errors.Is(err, firewall.ErrStateCorrupt) {
		t.Fatalf("executing over damaged state = %v", err)
	}
}

func TestFirewallActionReadRejectsInvalidBudgetMetadata(t *testing.T) {
	db := openSnapshotDB(t)
	s := actionStore(t, db)
	in := admissionFixture()
	if _, err := s.ReplaceFirewallState(0, in.Before); err != nil {
		t.Fatal(err)
	}
	a, _, err := s.AdmitFirewallAction(in)
	if err != nil {
		t.Fatal(err)
	}
	a.Budget.Limit = -1
	raw, err := encodeFirewallJournal(a)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.bolt.Update(func(tx *bolt.Tx) error { return tx.Bucket([]byte("fw:actions")).Put([]byte(a.Request.ID), raw) }); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ReadFirewallAction(a.Request.ID); !errors.Is(err, firewall.ErrStateCorrupt) {
		t.Fatalf("invalid persisted budget = %v", err)
	}
}

func TestFirewallActionRejectsMissingEvidenceObjects(t *testing.T) {
	for _, field := range []string{"before", "after"} {
		for _, missing := range []bool{false, true} {
			t.Run(field+map[bool]string{false: "-null", true: "-missing"}[missing], func(t *testing.T) {
				db := openSnapshotDB(t)
				in := admissionFixture()
				if _, err := db.ReplaceFirewallState(0, in.Before); err != nil {
					t.Fatal(err)
				}
				a, _, err := db.AdmitFirewallAction(in)
				if err != nil {
					t.Fatal(err)
				}
				raw, err := json.Marshal(a)
				if err != nil {
					t.Fatal(err)
				}
				var fields map[string]json.RawMessage
				if operationErr := json.Unmarshal(raw, &fields); operationErr != nil {
					t.Fatal(operationErr)
				}
				if missing {
					delete(fields, field)
				} else {
					fields[field] = json.RawMessage("null")
				}
				raw, err = encodeFirewallJournal(fields)
				if err != nil {
					t.Fatal(err)
				}
				if err := db.bolt.Update(func(tx *bolt.Tx) error {
					return tx.Bucket([]byte(firewallActionsBucket)).Put([]byte(a.Request.ID), raw)
				}); err != nil {
					t.Fatal(err)
				}
				if _, err := db.ReadFirewallAction(a.Request.ID); !errors.Is(err, firewall.ErrStateCorrupt) {
					t.Errorf("damaged evidence accepted: %v", err)
				}
				if _, err := db.TransitionFirewallAction(a.Request.ID, "failed", "", a.CreatedAt); !errors.Is(err, firewall.ErrStateCorrupt) {
					t.Errorf("damaged evidence used for rollback: %v", err)
				}
				assertFirewallSnapshot(t, db, in.Before, 1)
			})
		}
	}
}

func TestFirewallActionRejectsChangedBeforeEvidence(t *testing.T) {
	for _, phase := range []string{"planned", "executing", "failed", "verified"} {
		t.Run(phase, func(t *testing.T) {
			db := openSnapshotDB(t)
			in := admissionFixture()
			if _, err := db.ReplaceFirewallState(0, in.Before); err != nil {
				t.Fatal(err)
			}
			a, _, err := db.AdmitFirewallAction(in)
			if err != nil {
				t.Fatal(err)
			}
			a.Before = firewall.FirewallState{}
			raw, err := encodeFirewallJournal(a)
			if err != nil {
				t.Fatal(err)
			}
			if err := db.bolt.Update(func(tx *bolt.Tx) error {
				return tx.Bucket([]byte(firewallActionsBucket)).Put([]byte(a.Request.ID), raw)
			}); err != nil {
				t.Fatal(err)
			}
			if _, err := db.TransitionFirewallAction(a.Request.ID, phase, "", a.CreatedAt); !errors.Is(err, firewall.ErrStateCorrupt) {
				t.Errorf("changed evidence accepted: %v", err)
			}
			assertFirewallSnapshot(t, db, in.Before, 1)
		})
	}
}

func TestFirewallAuditRetainsEveryUnacknowledgedVersion(t *testing.T) {
	db := openSnapshotDB(t)
	in := admissionFixture()
	if _, err := db.ReplaceFirewallState(0, in.Before); err != nil {
		t.Fatal(err)
	}
	if _, _, err := db.AdmitFirewallAction(in); err != nil {
		t.Fatal(err)
	}
	unknown, err := db.TransitionFirewallAction(in.Request.ID, "unknown", "kernel reply unavailable", in.CreatedAt)
	if err != nil {
		t.Fatal(err)
	}
	terminal, err := db.TransitionFirewallAction(in.Request.ID, "verified", "kernel proved effect", in.CreatedAt)
	if err != nil {
		t.Fatal(err)
	}
	pending, err := db.FirewallAuditPending()
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 2 || !reflect.DeepEqual(pending[0], unknown) || !reflect.DeepEqual(pending[1], terminal) {
		t.Fatalf("audit version overwritten: %#v", pending)
	}
	// A late acknowledgement cannot consume a newer event, and retries are safe.
	for range 2 {
		if operationErr := db.AcknowledgeFirewallAudit(in.Request.ID, unknown.AuditVersion); operationErr != nil {
			t.Fatal(operationErr)
		}
	}
	pending, err = db.FirewallAuditPending()
	if err != nil || len(pending) != 1 || pending[0].AuditVersion != terminal.AuditVersion {
		t.Fatalf("late acknowledgement erased new audit: %#v %v", pending, err)
	}
	if operationErr := db.AcknowledgeFirewallAudit(in.Request.ID, terminal.AuditVersion); operationErr != nil {
		t.Fatal(operationErr)
	}
	if operationErr := db.AcknowledgeFirewallAudit(in.Request.ID, unknown.AuditVersion); operationErr != nil {
		t.Fatal(operationErr)
	}
	current, err := db.ReadFirewallAction(in.Request.ID)
	if err != nil || current.AuditAck != terminal.AuditVersion {
		t.Fatalf("acknowledgement moved backward: %#v %v", current, err)
	}
}

func TestFirewallActionLostCommitAcknowledgements(t *testing.T) {
	db := openSnapshotDB(t)
	in := admissionFixture()
	if _, err := db.ReplaceFirewallState(0, in.Before); err != nil {
		t.Fatal(err)
	}
	previous := boltUpdate
	t.Cleanup(func() { boltUpdate = previous })
	failure := errors.New("lost durable commit acknowledgement")
	loseAck := func(b *bolt.DB, fn func(*bolt.Tx) error) error {
		if err := b.Update(fn); err != nil {
			return err
		}
		return failure
	}
	boltUpdate = loseAck
	if _, fresh, err := db.AdmitFirewallAction(in); fresh || !errors.Is(err, firewall.ErrStateCommitUncertain) || !errors.Is(err, failure) {
		t.Fatalf("admission uncertainty lost: fresh=%v %v", fresh, err)
	}
	boltUpdate = previous
	original, err := db.ReadFirewallAction(in.Request.ID)
	if err != nil || original.Phase != "planned" {
		t.Fatalf("admission not visible: %#v %v", original, err)
	}
	retry, fresh, err := db.AdmitFirewallAction(in)
	if err != nil || fresh || !reflect.DeepEqual(original, retry) {
		t.Fatalf("admission retry changed evidence: %#v fresh=%v %v", retry, fresh, err)
	}
	count, err := db.ReadFirewallScanBudget(in.Budget.Window)
	if err != nil || count != 1 {
		t.Fatalf("duplicate budget: %d %v", count, err)
	}
	boltUpdate = loseAck
	if _, operationErr := db.TransitionFirewallAction(in.Request.ID, "verified", "proved", in.CreatedAt); !errors.Is(operationErr, firewall.ErrStateCommitUncertain) {
		t.Fatalf("outcome uncertainty lost: %v", operationErr)
	}
	boltUpdate = previous
	assertFirewallSnapshot(t, db, in.After, 2)
	terminal, err := db.ReadFirewallAction(in.Request.ID)
	if err != nil || terminal.Phase != "verified" {
		t.Fatalf("terminal action not visible: %#v %v", terminal, err)
	}
	if _, operationErr := db.TransitionFirewallAction(in.Request.ID, "verified", "proved", in.CreatedAt); operationErr != nil {
		t.Fatal(operationErr)
	}
	assertFirewallSnapshot(t, db, in.After, 2)
	boltUpdate = loseAck
	if operationErr := db.AcknowledgeFirewallAudit(in.Request.ID, terminal.AuditVersion); !errors.Is(operationErr, firewall.ErrStateCommitUncertain) {
		t.Fatalf("audit uncertainty lost: %v", operationErr)
	}
	boltUpdate = previous
	pending, err := db.FirewallAuditPending()
	if err != nil || len(pending) != 0 {
		t.Fatalf("committed audit ack not visible: %#v %v", pending, err)
	}
	if err := db.AcknowledgeFirewallAudit(in.Request.ID, terminal.AuditVersion); err != nil {
		t.Fatal(err)
	}
	if _, fresh, err := db.AdmitFirewallAction(in); fresh || err != nil {
		t.Fatalf("terminal replay admitted again: %v %v", fresh, err)
	}
}

func TestFirewallAuditAcknowledgesVersionsOutOfOrder(t *testing.T) {
	db := openSnapshotDB(t)
	in := admissionFixture()
	if _, err := db.ReplaceFirewallState(0, in.Before); err != nil {
		t.Fatal(err)
	}
	if _, _, err := db.AdmitFirewallAction(in); err != nil {
		t.Fatal(err)
	}
	older, err := db.TransitionFirewallAction(in.Request.ID, "unknown", "unobserved", in.CreatedAt)
	if err != nil {
		t.Fatal(err)
	}
	newer, err := db.TransitionFirewallAction(in.Request.ID, "verified", "observed", in.CreatedAt)
	if err != nil {
		t.Fatal(err)
	}
	if operationErr := db.AcknowledgeFirewallAudit(in.Request.ID, newer.AuditVersion); operationErr != nil {
		t.Fatal(operationErr)
	}
	pending, err := db.FirewallAuditPending()
	if err != nil || len(pending) != 1 || pending[0].AuditVersion != older.AuditVersion {
		t.Fatalf("new acknowledgement erased older event: %#v %v", pending, err)
	}
	if operationErr := db.AcknowledgeFirewallAudit(in.Request.ID, older.AuditVersion); operationErr != nil {
		t.Fatal(operationErr)
	}
	current, err := db.ReadFirewallAction(in.Request.ID)
	if err != nil || current.AuditAck != newer.AuditVersion {
		t.Fatalf("out-of-order acknowledgement regressed: %#v %v", current, err)
	}
}

func TestFirewallAuditCorruptionNeverReturnsPartialDelivery(t *testing.T) {
	for _, damage := range []string{"missing bucket", "nested event", "malformed event"} {
		t.Run(damage, func(t *testing.T) {
			db := openSnapshotDB(t)
			in := admissionFixture()
			if _, err := db.ReplaceFirewallState(0, in.Before); err != nil {
				t.Fatal(err)
			}
			if _, _, err := db.AdmitFirewallAction(in); err != nil {
				t.Fatal(err)
			}
			if _, err := db.TransitionFirewallAction(in.Request.ID, "verified", "proved", in.CreatedAt); err != nil {
				t.Fatal(err)
			}
			if err := db.bolt.Update(func(tx *bolt.Tx) error {
				b := tx.Bucket([]byte(firewallAuditBucket))
				switch damage {
				case "missing bucket":
					return tx.DeleteBucket([]byte(firewallAuditBucket))
				case "nested event":
					key, _ := b.Cursor().First()
					copied := bytes.Clone(key)
					if err := b.Delete(copied); err != nil {
						return err
					}
					_, err := b.CreateBucket(copied)
					return err
				default:
					key, _ := b.Cursor().First()
					return b.Put(bytes.Clone(key), []byte(`{"action":null}`))
				}
			}); err != nil {
				t.Fatal(err)
			}
			pending, err := db.FirewallAuditPending()
			if !errors.Is(err, firewall.ErrStateCorrupt) || pending != nil {
				t.Fatalf("audit corruption returned usable work: %#v %v", pending, err)
			}
		})
	}
}

func TestFirewallActionIntegrityProtectsUndoEvidence(t *testing.T) {
	db := openSnapshotDB(t)
	in := admissionFixture()
	if _, err := db.ReplaceFirewallState(0, in.Before); err != nil {
		t.Fatal(err)
	}
	if _, _, err := db.AdmitFirewallAction(in); err != nil {
		t.Fatal(err)
	}
	if _, err := db.TransitionFirewallAction(in.Request.ID, "verified", "proved", in.CreatedAt); err != nil {
		t.Fatal(err)
	}
	if err := db.bolt.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(firewallActionsBucket))
		raw := bytes.Clone(bucket.Get([]byte(in.Request.ID)))
		start := bytes.Index(raw, []byte(`"before":`))
		if start < 0 {
			t.Fatal("journal lacks before evidence")
		}
		changed := bytes.Replace(raw[start:], []byte("203.0.113.90"), []byte("203.0.113.91"), 1)
		if bytes.Equal(raw[start:], changed) {
			t.Fatal("fixture did not mutate before identity")
		}
		return bucket.Put([]byte(in.Request.ID), append(raw[:start:start], changed...))
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ReadFirewallAction(in.Request.ID); !errors.Is(err, firewall.ErrStateCorrupt) {
		t.Errorf("valid JSON corruption accepted: %v", err)
	}
	lifecycle := lifecycleFor(t, db, func(firewall.FirewallAction) error { return nil })
	kernel := &observedKernel{state: in.After}
	req := firewall.ActionRequest{ID: "undo-corrupt", Operation: "undo", Actor: "cli", Source: "cli", UndoOf: in.Request.ID}
	if _, err := lifecycle.Undo(req, kernel); !errors.Is(err, firewall.ErrStateCorrupt) {
		t.Errorf("corrupt undo evidence admitted: %v", err)
	}
	if kernel.writes != 0 {
		t.Fatal("corrupt undo touched kernel")
	}
	assertFirewallSnapshot(t, db, in.After, 2)
}

func TestFirewallAuditIntegrityRejectsChangedPayloadAndAcknowledgement(t *testing.T) {
	for _, change := range []string{"payload", "acknowledgement"} {
		t.Run(change, func(t *testing.T) {
			db := openSnapshotDB(t)
			in := admissionFixture()
			if _, err := db.ReplaceFirewallState(0, in.Before); err != nil {
				t.Fatal(err)
			}
			if _, _, err := db.AdmitFirewallAction(in); err != nil {
				t.Fatal(err)
			}
			a, err := db.TransitionFirewallAction(in.Request.ID, "verified", "proved", in.CreatedAt)
			if err != nil {
				t.Fatal(err)
			}
			if updateErr := db.bolt.Update(func(tx *bolt.Tx) error {
				b := tx.Bucket([]byte(firewallAuditBucket))
				key := firewallAuditKey(a.Request.ID, a.AuditVersion)
				raw := bytes.Clone(b.Get(key))
				old, new := []byte(`"actor":"cli"`), []byte(`"actor":"clh"`)
				if change == "acknowledgement" {
					old, new = []byte(`"acknowledged":false`), []byte(`"acknowledged":true`)
				}
				changed := bytes.Replace(raw, old, new, 1)
				if bytes.Equal(raw, changed) {
					t.Fatal("fixture did not change audit")
				}
				return b.Put(key, changed)
			}); updateErr != nil {
				t.Fatal(updateErr)
			}
			pending, err := db.FirewallAuditPending()
			if !errors.Is(err, firewall.ErrStateCorrupt) || pending != nil {
				t.Fatalf("changed audit accepted: count=%d err=%v", len(pending), err)
			}
		})
	}
}

func TestFirewallActionRejectsUnknownOrMissingJournalEnvelope(t *testing.T) {
	for _, change := range []string{"version", "checksum", "payload"} {
		t.Run(change, func(t *testing.T) {
			db := openSnapshotDB(t)
			in := admissionFixture()
			if _, err := db.ReplaceFirewallState(0, in.Before); err != nil {
				t.Fatal(err)
			}
			if _, _, err := db.AdmitFirewallAction(in); err != nil {
				t.Fatal(err)
			}
			if err := db.bolt.Update(func(tx *bolt.Tx) error {
				b := tx.Bucket([]byte(firewallActionsBucket))
				var fields map[string]json.RawMessage
				if err := json.Unmarshal(b.Get([]byte(in.Request.ID)), &fields); err != nil {
					return err
				}
				switch change {
				case "version":
					fields["version"] = json.RawMessage("2")
				case "checksum":
					delete(fields, "sha256")
				default:
					fields["payload"] = json.RawMessage("null")
				}
				raw, err := json.Marshal(fields)
				if err != nil {
					return err
				}
				return b.Put([]byte(in.Request.ID), raw)
			}); err != nil {
				t.Fatal(err)
			}
			if _, err := db.ReadFirewallAction(in.Request.ID); !errors.Is(err, firewall.ErrStateCorrupt) {
				t.Fatalf("invalid journal envelope accepted: %v", err)
			}
		})
	}
}

func TestFirewallScanBudgetIntegrityRefusesReducedCount(t *testing.T) {
	db := openSnapshotDB(t)
	in := admissionFixture()
	if _, err := db.ReplaceFirewallState(0, in.Before); err != nil {
		t.Fatal(err)
	}
	if _, _, err := db.AdmitFirewallAction(in); err != nil {
		t.Fatal(err)
	}
	if _, err := db.TransitionFirewallAction(in.Request.ID, "failed", "not applied", in.CreatedAt); err != nil {
		t.Fatal(err)
	}
	if err := db.bolt.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(firewallBudgetBucket))
		raw := bytes.Clone(b.Get([]byte(in.Budget.Window)))
		changed := bytes.Replace(raw, []byte(`"count":1`), []byte(`"count":0`), 1)
		if bytes.Equal(raw, changed) {
			t.Fatal("fixture did not reduce budget")
		}
		return b.Put([]byte(in.Budget.Window), changed)
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ReadFirewallScanBudget(in.Budget.Window); !errors.Is(err, firewall.ErrStateCorrupt) {
		t.Errorf("reduced counter accepted: %v", err)
	}
	in.Request.ID = "next-budget-request"
	in.Revision = 2
	kernel := &observedKernel{state: in.Before}
	lifecycle := lifecycleFor(t, db, func(firewall.FirewallAction) error { return nil })
	if _, err := lifecycle.Execute(in, kernel); !errors.Is(err, firewall.ErrStateCorrupt) {
		t.Errorf("reduced budget admitted: %v", err)
	}
	if kernel.writes != 0 {
		t.Fatal("corrupt budget reached kernel")
	}
	assertFirewallSnapshot(t, db, in.Before, 2)
}

func TestFirewallScanBudgetIntegrityBindsWindow(t *testing.T) {
	db := openSnapshotDB(t)
	in := admissionFixture()
	if _, err := db.ReplaceFirewallState(0, in.Before); err != nil {
		t.Fatal(err)
	}
	if _, _, err := db.AdmitFirewallAction(in); err != nil {
		t.Fatal(err)
	}
	if _, err := db.TransitionFirewallAction(in.Request.ID, "failed", "not applied", in.CreatedAt); err != nil {
		t.Fatal(err)
	}
	later := admissionFixture()
	later.Request.ID = "later-window"
	later.Revision = 2
	later.Budget.Window = "2026-01-02T04"
	if _, _, err := db.AdmitFirewallAction(later); err != nil {
		t.Fatal(err)
	}
	if err := db.bolt.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(firewallBudgetBucket))
		return b.Put([]byte("2026-01-02T04"), bytes.Clone(b.Get([]byte(in.Budget.Window))))
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ReadFirewallScanBudget("2026-01-02T04"); !errors.Is(err, firewall.ErrStateCorrupt) {
		t.Fatalf("counter reused in different window: %v", err)
	}
}

func TestFirewallScanBudgetRejectsInvalidCountWithValidChecksum(t *testing.T) {
	for _, count := range []any{0, -1, "1", nil} {
		db := openSnapshotDB(t)
		in := admissionFixture()
		if _, err := db.ReplaceFirewallState(0, in.Before); err != nil {
			t.Fatal(err)
		}
		if _, _, err := db.AdmitFirewallAction(in); err != nil {
			t.Fatal(err)
		}
		raw, err := encodeFirewallJournal(map[string]any{"window": "2026-01-02T03", "count": count})
		if err != nil {
			t.Fatal(err)
		}
		if err := db.bolt.Update(func(tx *bolt.Tx) error {
			b, err := tx.CreateBucketIfNotExists([]byte(firewallBudgetBucket))
			if err != nil {
				return err
			}
			return b.Put([]byte("2026-01-02T03"), raw)
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := db.ReadFirewallScanBudget("2026-01-02T03"); !errors.Is(err, firewall.ErrStateCorrupt) {
			t.Errorf("invalid count accepted: %v", err)
		}
	}
}

func TestFirewallJournalIndexesAvoidTerminalHistoryDecoding(t *testing.T) {
	db := openSnapshotDB(t)
	in := admissionFixture()
	if _, err := db.ReplaceFirewallState(0, in.Before); err != nil {
		t.Fatal(err)
	}
	if _, _, err := db.AdmitFirewallAction(in); err != nil {
		t.Fatal(err)
	}
	terminal, err := db.TransitionFirewallAction(in.Request.ID, "failed", "not applied", in.CreatedAt)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AcknowledgeFirewallAudit(in.Request.ID, terminal.AuditVersion); err != nil {
		t.Fatal(err)
	}
	if err := db.bolt.Update(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte(firewallActionsBucket)).Put([]byte(in.Request.ID), []byte(`{"corrupt":"terminal evidence"}`))
	}); err != nil {
		t.Fatal(err)
	}
	if pending, err := db.PendingFirewallActions(); err != nil || len(pending) != 0 {
		t.Errorf("pending lookup scanned terminal history: count=%d err=%v", len(pending), err)
	}
	if pending, err := db.FirewallAuditPending(); err != nil || len(pending) != 0 {
		t.Errorf("audit lookup scanned terminal history: count=%d err=%v", len(pending), err)
	}
	if _, err := db.ReadFirewallAction(in.Request.ID); !errors.Is(err, firewall.ErrStateCorrupt) {
		t.Error("history lookup ignored corrupt evidence")
	}
	next := in
	next.Request.ID = "indexed-next"
	next.Revision = 2
	next.Budget = nil
	if _, _, err := db.AdmitFirewallAction(next); err != nil {
		t.Fatalf("admission scanned unrelated terminal history: %v", err)
	}
}

func TestFirewallJournalMissingIndexOrReferenceFailsClosed(t *testing.T) {
	for _, damage := range []string{"metadata bucket", "metadata value", "metadata checksum", "pending action", "pending audit"} {
		t.Run(damage, func(t *testing.T) {
			db := openSnapshotDB(t)
			in := admissionFixture()
			if _, err := db.ReplaceFirewallState(0, in.Before); err != nil {
				t.Fatal(err)
			}
			if _, _, err := db.AdmitFirewallAction(in); err != nil {
				t.Fatal(err)
			}
			a, err := db.TransitionFirewallAction(in.Request.ID, "unknown", "needs inspection", in.CreatedAt)
			if err != nil {
				t.Fatal(err)
			}
			if err := db.bolt.Update(func(tx *bolt.Tx) error {
				meta := tx.Bucket([]byte("fw:action_index"))
				if meta == nil {
					return errors.New("journal index was not initialized")
				}
				switch damage {
				case "metadata bucket":
					return tx.DeleteBucket([]byte("fw:action_index"))
				case "metadata value":
					return meta.Delete([]byte("index"))
				case "metadata checksum":
					return meta.Put([]byte("index"), []byte(`{"version":1,"payload":{},"sha256":"damaged"}`))
				case "pending action":
					return tx.Bucket([]byte(firewallActionsBucket)).Delete([]byte(in.Request.ID))
				default:
					return tx.Bucket([]byte(firewallAuditBucket)).Delete(firewallAuditKey(a.Request.ID, a.AuditVersion))
				}
			}); err != nil {
				t.Fatal(err)
			}
			if damage != "pending audit" {
				if pending, err := db.PendingFirewallActions(); !errors.Is(err, firewall.ErrStateCorrupt) || pending != nil {
					t.Errorf("damaged pending index accepted: count=%d err=%v", len(pending), err)
				}
				next := in
				next.Request.ID = "conflicting-new"
				next.Budget = nil
				if _, _, err := db.AdmitFirewallAction(next); !errors.Is(err, firewall.ErrStateCorrupt) {
					t.Errorf("damaged index admitted work: %v", err)
				}
			}
			if damage != "pending action" {
				if pending, err := db.FirewallAuditPending(); !errors.Is(err, firewall.ErrStateCorrupt) || pending != nil {
					t.Errorf("damaged audit index accepted: count=%d err=%v", len(pending), err)
				}
			}
		})
	}
}

func TestFirewallJournalRejectsMalformedInitializedIndex(t *testing.T) {
	for name, payload := range map[string]string{
		"uninitialized":         `{"initialized":false,"pending_id":"request-one","audit":[]}`,
		"missing pending field": `{"initialized":true,"audit":[]}`,
		"missing audit field":   `{"initialized":true,"pending_id":"request-one"}`,
		"duplicate audit":       `{"initialized":true,"pending_id":"request-one","audit":[{"id":"request-one","version":2},{"id":"request-one","version":2}]}`,
		"invalid audit":         `{"initialized":true,"pending_id":"request-one","audit":[{"id":"","version":0}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			db := openSnapshotDB(t)
			in := admissionFixture()
			if _, err := db.ReplaceFirewallState(0, in.Before); err != nil {
				t.Fatal(err)
			}
			if _, _, err := db.AdmitFirewallAction(in); err != nil {
				t.Fatal(err)
			}
			raw, err := encodeFirewallJournal(json.RawMessage(payload))
			if err != nil {
				t.Fatal(err)
			}
			if err := db.bolt.Update(func(tx *bolt.Tx) error { return tx.Bucket([]byte("fw:action_index")).Put([]byte("index"), raw) }); err != nil {
				t.Fatal(err)
			}
			if pending, err := db.PendingFirewallActions(); !errors.Is(err, firewall.ErrStateCorrupt) || pending != nil {
				t.Fatalf("malformed index accepted: %v %v", pending, err)
			}
			if audits, err := db.FirewallAuditPending(); !errors.Is(err, firewall.ErrStateCorrupt) || audits != nil {
				t.Fatalf("malformed index accepted: %v %v", audits, err)
			}
		})
	}
}

func TestFirewallJournalIndexRollbackKeepsPendingReferences(t *testing.T) {
	db := openSnapshotDB(t)
	in := admissionFixture()
	if _, err := db.ReplaceFirewallState(0, in.Before); err != nil {
		t.Fatal(err)
	}
	if _, _, err := db.AdmitFirewallAction(in); err != nil {
		t.Fatal(err)
	}
	previous := boltUpdate
	t.Cleanup(func() { boltUpdate = previous })
	fail := errors.New("transaction rolled back")
	boltUpdate = func(b *bolt.DB, fn func(*bolt.Tx) error) error {
		return b.Update(func(tx *bolt.Tx) error {
			if callbackErr := fn(tx); callbackErr != nil {
				return callbackErr
			}
			return fail
		})
	}
	if _, err := db.TransitionFirewallAction(in.Request.ID, "verified", "proved", in.CreatedAt); !errors.Is(err, fail) {
		t.Fatal(err)
	}
	pending, err := db.PendingFirewallActions()
	if err != nil || len(pending) != 1 || pending[0].Phase != "planned" {
		t.Fatalf("rollback lost pending action: %#v %v", pending, err)
	}
	audits, err := db.FirewallAuditPending()
	if err != nil || len(audits) != 0 {
		t.Fatalf("rollback retained orphan audit index: %#v %v", audits, err)
	}
	boltUpdate = previous
	done, err := db.TransitionFirewallAction(in.Request.ID, "verified", "proved", in.CreatedAt)
	if err != nil {
		t.Fatal(err)
	}
	boltUpdate = func(b *bolt.DB, fn func(*bolt.Tx) error) error {
		return b.Update(func(tx *bolt.Tx) error {
			if callbackErr := fn(tx); callbackErr != nil {
				return callbackErr
			}
			return fail
		})
	}
	if ackErr := db.AcknowledgeFirewallAudit(done.Request.ID, done.AuditVersion); !errors.Is(ackErr, fail) {
		t.Fatal(ackErr)
	}
	audits, err = db.FirewallAuditPending()
	if err != nil || len(audits) != 1 || audits[0].AuditVersion != done.AuditVersion {
		t.Fatalf("ack rollback erased pending audit: %#v %v", audits, err)
	}
}

func BenchmarkFirewallJournalTerminalHistory(b *testing.B) {
	for _, history := range []int{1, 100, 1000} {
		b.Run(fmt.Sprintf("terminal=%d", history), func(b *testing.B) {
			db, err := Open(b.TempDir())
			if err != nil {
				b.Fatal(err)
			}
			b.Cleanup(func() { _ = db.Close() })
			in := admissionFixture()
			in.Budget = nil
			if _, setupErr := db.ReplaceFirewallState(0, in.Before); setupErr != nil {
				b.Fatal(setupErr)
			}
			if _, _, setupErr := db.AdmitFirewallAction(in); setupErr != nil {
				b.Fatal(setupErr)
			}
			terminal, err := db.TransitionFirewallAction(in.Request.ID, "failed", "not applied", in.CreatedAt)
			if err != nil {
				b.Fatal(err)
			}
			if err := db.AcknowledgeFirewallAudit(in.Request.ID, terminal.AuditVersion); err != nil {
				b.Fatal(err)
			}
			// Populate retained completed records outside the measured operation.
			// They have no outstanding recovery or audit work.
			if err := db.bolt.Update(func(tx *bolt.Tx) error {
				for i := 1; i < history; i++ {
					old := terminal
					old.Request.ID = fmt.Sprintf("history-%06d", i)
					actionRaw, encodeErr := encodeFirewallJournal(old)
					if encodeErr != nil {
						return encodeErr
					}
					old.AuditAck = old.AuditVersion
					if _, writeErr := writeFirewallAction(tx, old); writeErr != nil {
						return writeErr
					}
					eventRaw, encodeErr := encodeFirewallJournal(firewallAuditEvent{Action: actionRaw, Acknowledged: true})
					if encodeErr != nil {
						return encodeErr
					}
					if putErr := tx.Bucket([]byte(firewallAuditBucket)).Put(firewallAuditKey(old.Request.ID, old.AuditVersion), eventRaw); putErr != nil {
						return putErr
					}
				}
				return nil
			}); err != nil {
				b.Fatal(err)
			}
			b.Run("pending", func(b *testing.B) {
				b.ReportAllocs()
				b.ResetTimer()
				for b.Loop() {
					if _, err := db.PendingFirewallActions(); err != nil {
						b.Fatal(err)
					}
				}
			})
			b.Run("audit", func(b *testing.B) {
				b.ReportAllocs()
				b.ResetTimer()
				for b.Loop() {
					if _, err := db.FirewallAuditPending(); err != nil {
						b.Fatal(err)
					}
				}
			})
			b.Run("admission", func(b *testing.B) {
				b.ReportAllocs()
				b.ResetTimer()
				for b.Loop() {
					// Roll back after the real admission callback, isolating lookup and
					// admission cost from growing history during benchmark calibration.
					candidate := in
					candidate.Request.ID = "benchmark-candidate"
					candidate.Revision = 2
					original := boltUpdate
					rollback := errors.New("benchmark rollback")
					boltUpdate = func(b *bolt.DB, fn func(*bolt.Tx) error) error {
						return b.Update(func(tx *bolt.Tx) error {
							if err := fn(tx); err != nil {
								return err
							}
							return rollback
						})
					}
					_, _, err := db.AdmitFirewallAction(candidate)
					boltUpdate = original
					if !errors.Is(err, rollback) {
						b.Fatal(err)
					}
				}
			})
		})
	}
}

func TestFirewallJournalReplayRejectsMissingPendingReference(t *testing.T) {
	db := openSnapshotDB(t)
	original := admissionFixture()
	original.Budget = nil
	if _, err := db.ReplaceFirewallState(0, original.Before); err != nil {
		t.Fatal(err)
	}
	if _, _, err := db.AdmitFirewallAction(original); err != nil {
		t.Fatal(err)
	}
	if _, err := db.TransitionFirewallAction(original.Request.ID, "failed", "not applied", original.CreatedAt); err != nil {
		t.Fatal(err)
	}
	next := original
	next.Request.ID = "missing-pending"
	next.Revision = 2
	if _, _, err := db.AdmitFirewallAction(next); err != nil {
		t.Fatal(err)
	}
	if err := db.bolt.Update(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte(firewallActionsBucket)).Delete([]byte(next.Request.ID))
	}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := db.AdmitFirewallAction(original); !errors.Is(err, firewall.ErrStateCorrupt) {
		t.Fatalf("replay ignored corrupt pending reference: %v", err)
	}
}

func TestFirewallScanBudgetDeletionRefusesAdmission(t *testing.T) {
	for _, damage := range []string{"counter", "budget bucket", "inventory bucket", "inventory value", "inventory checksum"} {
		t.Run(damage, func(t *testing.T) {
			db := openSnapshotDB(t)
			in := admissionFixture()
			if _, err := db.ReplaceFirewallState(0, in.Before); err != nil {
				t.Fatal(err)
			}
			if _, _, err := db.AdmitFirewallAction(in); err != nil {
				t.Fatal(err)
			}
			if _, err := db.TransitionFirewallAction(in.Request.ID, "failed", "not applied", in.CreatedAt); err != nil {
				t.Fatal(err)
			}
			if err := db.bolt.Update(func(tx *bolt.Tx) error {
				switch damage {
				case "counter":
					return tx.Bucket([]byte(firewallBudgetBucket)).Delete([]byte(in.Budget.Window))
				case "budget bucket":
					return tx.DeleteBucket([]byte(firewallBudgetBucket))
				case "inventory bucket":
					if tx.Bucket([]byte("fw:budget_index")) == nil {
						return errors.New("budget inventory not initialized")
					}
					return tx.DeleteBucket([]byte("fw:budget_index"))
				default:
					b := tx.Bucket([]byte("fw:budget_index"))
					if b == nil {
						return errors.New("budget inventory not initialized")
					}
					if damage == "inventory value" {
						return b.Delete([]byte("index"))
					}
					return b.Put([]byte("index"), []byte(`{"version":1,"payload":{},"sha256":"damaged"}`))
				}
			}); err != nil {
				t.Fatal(err)
			}
			if count, err := db.ReadFirewallScanBudget(in.Budget.Window); !errors.Is(err, firewall.ErrStateCorrupt) || count != 0 {
				t.Errorf("deleted budget read as unused: %d %v", count, err)
			}
			in.Request.ID = "after-deleted-budget"
			in.Revision = 2
			kernel := &observedKernel{state: in.Before}
			lifecycle := lifecycleFor(t, db, func(firewall.FirewallAction) error { return nil })
			if _, err := lifecycle.Execute(in, kernel); !errors.Is(err, firewall.ErrStateCorrupt) {
				t.Errorf("deleted budget admitted: %v", err)
			}
			if kernel.writes != 0 {
				t.Fatal("deleted budget reached kernel")
			}
			assertFirewallSnapshot(t, db, in.Before, 2)
		})
	}
}

func TestFirewallScanBudgetUnusedWindowRemainsZero(t *testing.T) {
	db := openSnapshotDB(t)
	if count, err := db.ReadFirewallScanBudget("2026-01-02T03"); err != nil || count != 0 {
		t.Fatalf("fresh window: %d %v", count, err)
	}
	in := admissionFixture()
	if _, err := db.ReplaceFirewallState(0, in.Before); err != nil {
		t.Fatal(err)
	}
	if _, _, err := db.AdmitFirewallAction(in); err != nil {
		t.Fatal(err)
	}
	if count, err := db.ReadFirewallScanBudget("2026-01-02T04"); err != nil || count != 0 {
		t.Fatalf("unused later window: %d %v", count, err)
	}
	if count, err := db.ReadFirewallScanBudget(in.Budget.Window); err != nil || count != 1 {
		t.Fatalf("used window: %d %v", count, err)
	}
}

func TestFirewallScanBudgetInventoryRejectsMalformedMetadata(t *testing.T) {
	for _, payload := range []string{
		`{"initialized":false,"windows":[]}`,
		`{"initialized":true}`,
		`{"initialized":true,"windows":null}`,
		`{"initialized":true,"windows":["invalid"]}`,
		`{"initialized":true,"windows":["2026-01-02T03","2026-01-02T03"]}`,
		`{"initialized":true,"windows":["2026-01-02T04","2026-01-02T03"]}`,
	} {
		t.Run(payload, func(t *testing.T) {
			db := openSnapshotDB(t)
			in := admissionFixture()
			if _, err := db.ReplaceFirewallState(0, in.Before); err != nil {
				t.Fatal(err)
			}
			if _, _, err := db.AdmitFirewallAction(in); err != nil {
				t.Fatal(err)
			}
			raw, err := encodeFirewallJournal(json.RawMessage(payload))
			if err != nil {
				t.Fatal(err)
			}
			if err := db.bolt.Update(func(tx *bolt.Tx) error { return tx.Bucket([]byte("fw:budget_index")).Put([]byte("index"), raw) }); err != nil {
				t.Fatal(err)
			}
			if _, err := db.ReadFirewallScanBudget(in.Budget.Window); !errors.Is(err, firewall.ErrStateCorrupt) {
				t.Fatalf("malformed inventory accepted: %v", err)
			}
		})
	}
}

func TestFirewallScanBudgetNewWindowInventoryRollsBack(t *testing.T) {
	db := openSnapshotDB(t)
	in := admissionFixture()
	if _, err := db.ReplaceFirewallState(0, in.Before); err != nil {
		t.Fatal(err)
	}
	if _, _, err := db.AdmitFirewallAction(in); err != nil {
		t.Fatal(err)
	}
	if _, err := db.TransitionFirewallAction(in.Request.ID, "failed", "not applied", in.CreatedAt); err != nil {
		t.Fatal(err)
	}
	previous := boltUpdate
	t.Cleanup(func() { boltUpdate = previous })
	failure := errors.New("rollback new budget window")
	boltUpdate = func(db *bolt.DB, fn func(*bolt.Tx) error) error {
		return db.Update(func(tx *bolt.Tx) error {
			if err := fn(tx); err != nil {
				return err
			}
			return failure
		})
	}
	next := admissionFixture()
	next.Request.ID = "new-window"
	next.Revision = 2
	next.Budget.Window = "2026-01-02T04"
	if _, _, err := db.AdmitFirewallAction(next); !errors.Is(err, failure) {
		t.Fatalf("rollback failed: %v", err)
	}
	if count, err := db.ReadFirewallScanBudget(next.Budget.Window); err != nil || count != 0 {
		t.Fatalf("orphan window inventory: %d %v", count, err)
	}
	if count, err := db.ReadFirewallScanBudget(in.Budget.Window); err != nil || count != 1 {
		t.Fatalf("old window lost: %d %v", count, err)
	}
	boltUpdate = previous
	if _, _, err := db.AdmitFirewallAction(next); err != nil {
		t.Fatal(err)
	}
	if count, err := db.ReadFirewallScanBudget(next.Budget.Window); err != nil || count != 1 {
		t.Fatalf("window not charged: %d %v", count, err)
	}
}
