package store

import (
	"bytes"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/firewall"
	bolt "go.etcd.io/bbolt"
)

func TestFirewallRetireSharedTransitionSurvivesCommitFaults(t *testing.T) {
	for _, kind := range []string{"retire", "verified", "failed"} {
		for _, lost := range []bool{false, true} {
			t.Run(kind+map[bool]string{false: " rollback", true: " lost ack"}[lost], func(t *testing.T) {
				db := openSnapshotDB(t)
				a := unknownBatch(t, db, true)
				before := batchIndexImage(t, db)
				at := time.Now().UTC().Round(0)
				transition := func() (firewall.FirewallAction, error) {
					if kind == "retire" {
						return db.RetireFirewallAction(a.Request.ID, at)
					}
					return db.TransitionFirewallAction(a.Request.ID, kind, "resolved", at)
				}
				previous := boltUpdate
				t.Cleanup(func() { boltUpdate = previous })
				cause := errors.New("commit fault")
				boltUpdate = func(b *bolt.DB, fn func(*bolt.Tx) error) error {
					if lost {
						if err := b.Update(fn); err != nil {
							return err
						}
						return cause
					}
					return b.Update(func(tx *bolt.Tx) error {
						if err := fn(tx); err != nil {
							return err
						}
						return cause
					})
				}
				if _, err := transition(); err == nil {
					t.Fatal("commit fault hidden")
				}
				boltUpdate = previous
				if !lost && !bytes.Equal(before, batchIndexImage(t, db)) {
					t.Fatal("failed transaction leaked snapshot or journal changes")
				}
				got, err := transition()
				if err != nil || got.AuditVersion != a.AuditVersion+1 || got.Retired != (kind == "retire") {
					t.Fatalf("retry: %#v %v", got, err)
				}
				want := a.Before
				if kind == "verified" {
					want = a.After
				}
				assertFirewallSnapshot(t, db, want, 2)
				if pending, pendingErr := db.PendingFirewallActions(); pendingErr != nil || len(pending) != 0 {
					t.Fatalf("pending: %#v %v", pending, pendingErr)
				}
				audit, err := db.FirewallAuditPending()
				if err != nil || len(audit) != 1 || audit[0].AuditVersion != got.AuditVersion {
					t.Fatalf("audit: %#v %v", audit, err)
				}
				member, err := db.ReadFirewallBatchMember("member-1")
				if err != nil || !member.SameManifest(a) {
					t.Fatalf("lost member index: %#v %v", member, err)
				}
				if n, err := db.ReadFirewallScanBudget(a.Members[0].Budget.Window); err != nil || n != 2 {
					t.Fatalf("charges: %d %v", n, err)
				}
			})
		}
	}
}

func TestFirewallRetiredRejectsIdenticalTransitionAndUndo(t *testing.T) {
	db := openSnapshotDB(t)
	a := unknownBatch(t, db, true)
	retired, err := db.RetireFirewallAction(a.Request.ID, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	image := batchIndexImage(t, db)
	if _, err := db.TransitionFirewallAction(a.Request.ID, "unknown", retired.Detail, retired.UpdatedAt); !errors.Is(err, firewall.ErrStateConflict) {
		t.Fatalf("identical retired transition: %v", err)
	}
	l := lifecycleFor(t, db, func(firewall.FirewallAction) error { return nil })
	for _, id := range []string{a.Request.ID, "member-1"} {
		if _, err := l.Undo(undoOf("inverse", id), &observedKernel{}); err == nil {
			t.Fatalf("retired %s undone", id)
		}
	}
	if !bytes.Equal(image, batchIndexImage(t, db)) {
		t.Fatal("retired refusal changed journal")
	}
}

func TestFirewallRetiredHistorySurvivesRebuildAndSweep(t *testing.T) {
	for _, rebuild := range []bool{false, true} {
		t.Run(map[bool]string{false: "indexed", true: "rebuilt"}[rebuild], func(t *testing.T) {
			db := openSnapshotDB(t)
			a := unknownBatch(t, db, true)
			at := time.Now().UTC().Round(0)
			retired, err := db.RetireFirewallAction(a.Request.ID, at)
			if err != nil {
				t.Fatal(err)
			}
			if rebuild {
				if err := db.bolt.Update(func(tx *bolt.Tx) error { return tx.DeleteBucket([]byte(firewallActionHistoryBucket)) }); err != nil {
					t.Fatal(err)
				}
			}
			if n, err := db.SweepFirewallActionsOlderThan(at.Add(time.Second)); err != nil || n != 0 {
				t.Fatalf("undelivered retirement swept: %d %v", n, err)
			}
			if err := db.bolt.View(func(tx *bolt.Tx) error {
				entries, _, err := readFirewallActionHistory(tx)
				if err != nil || len(entries) != 1 || entries[0].id != a.Request.ID {
					t.Fatalf("retired history index: %#v %v", entries, err)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			if got, err := db.ReadFirewallBatchMember("member-1"); err != nil || !got.Retired || !got.SameManifest(a) {
				t.Fatalf("undelivered member lost: %#v %v", got, err)
			}
			if audit, err := db.FirewallAuditPending(); err != nil || len(audit) != 1 || !audit[0].Retired || audit[0].AuditVersion != retired.AuditVersion {
				t.Fatalf("undelivered audit lost: %#v %v", audit, err)
			}
			assertFirewallSnapshot(t, db, a.Before, 2)
			if err := db.AcknowledgeFirewallAudit(a.Request.ID, retired.AuditVersion); err != nil {
				t.Fatal(err)
			}
			if n, err := db.SweepFirewallActionsOlderThan(at.Add(time.Second)); err != nil || n != 1 {
				t.Fatalf("retired history not swept: %d %v", n, err)
			}
			if _, err := db.ReadFirewallBatchMember("member-1"); !errors.Is(err, firewall.ErrActionMissing) {
				t.Fatalf("swept member index: %v", err)
			}
			if _, err := db.ReadFirewallAction(a.Request.ID); !errors.Is(err, firewall.ErrActionMissing) {
				t.Fatalf("swept action: %v", err)
			}
			if audit, err := db.FirewallAuditPending(); err != nil || len(audit) != 0 {
				t.Fatalf("swept audit: %#v %v", audit, err)
			}
			assertFirewallSnapshot(t, db, a.Before, 2)
		})
	}
}

type retireFailureStore struct {
	*DB
	fail error
}

func (s retireFailureStore) RetireFirewallAction(string, time.Time) (firewall.FirewallAction, error) {
	return firewall.FirewallAction{}, s.fail
}

func TestFirewallRecoverRetiresWithoutHidingErrors(t *testing.T) {
	for _, stage := range []string{"observe", "outcome", "prove", "retire", "audit", "ack"} {
		t.Run(stage, func(t *testing.T) {
			db := openSnapshotDB(t)
			a := unknownBatch(t, db, true)
			cause := errors.New("failure at " + stage)
			k := &retiringKernel{proven: true, at: time.Now().UTC()}
			l := &firewall.Lifecycle{Store: db, Audit: func(row firewall.FirewallAction) error {
				if row.Retired && stage == "audit" {
					return cause
				}
				return nil
			}}
			if stage == "observe" {
				k.observeFail = cause
			}
			if stage == "outcome" {
				l.Store = retireOutcomeFailureStore{DB: db, fail: cause}
			}
			if stage == "prove" {
				k.proofErr = cause
			}
			if stage == "retire" {
				l.Store = retireFailureStore{db, cause}
			}
			if stage == "ack" {
				l.Store = &retireAckFailureStore{DB: db, fail: cause}
			}
			err := l.Recover(k)
			if !errors.Is(err, cause) {
				t.Fatalf("lost %s error: %v", stage, err)
			}
			got, readErr := db.ReadFirewallAction(a.Request.ID)
			wantRetired := stage != "prove" && stage != "retire" && stage != "outcome"
			if readErr != nil || got.Retired != wantRetired || k.writes != 0 {
				t.Fatalf("recovery state: %#v %v writes %d", got, readErr, k.writes)
			}
			if stage == "outcome" && k.calls != 0 {
				t.Fatal("retirement followed a failed outcome write")
			}
			if !wantRetired && !errors.Is(err, firewall.ErrActionUnknown) {
				t.Fatalf("lost pending outcome: %v", err)
			}
			// An audit/ack retry cannot repeat the checkpoint or its kernel writes.
			if stage == "audit" || stage == "ack" {
				l.Store = db
				l.Audit = func(firewall.FirewallAction) error { return nil }
				image, rev, readErr := db.ReadFirewallState()
				if readErr != nil {
					t.Fatal(readErr)
				}
				if err := l.Recover(k); err != nil {
					t.Fatal(err)
				}
				state, revision, readErr := db.ReadFirewallState()
				if readErr != nil || revision != rev || !reflect.DeepEqual(state, image) || k.writes != 0 {
					t.Fatalf("audit retry repeated checkpoint: %d %v", revision, readErr)
				}
			}
		})
	}
}

type retireAckFailureStore struct {
	*DB
	fail error
}

func (s *retireAckFailureStore) AcknowledgeFirewallAudit(id string, version uint64) error {
	a, err := s.ReadFirewallAction(id)
	if err != nil {
		return err
	}
	if a.Retired {
		return s.fail
	}
	return s.DB.AcknowledgeFirewallAudit(id, version)
}

type retireOutcomeFailureStore struct {
	*DB
	fail error
}

func (s retireOutcomeFailureStore) TransitionFirewallAction(string, string, string, time.Time) (firewall.FirewallAction, error) {
	return firewall.FirewallAction{}, s.fail
}

type retirementAuditReadStore struct {
	*DB
	reads int
}

func (s *retirementAuditReadStore) FirewallAuditPending() ([]firewall.FirewallAction, error) {
	s.reads++
	return s.DB.FirewallAuditPending()
}

// Only a newly committed retirement creates work for a second audit pass.
func TestFirewallRecoverRetiresThenDeliversAgain(t *testing.T) {
	for _, mode := range []string{"no pending", "not proven", "retired"} {
		t.Run(mode, func(t *testing.T) {
			db := openSnapshotDB(t)
			if mode != "no pending" {
				unknownBatch(t, db, true)
			}
			store := &retirementAuditReadStore{DB: db}
			l := &firewall.Lifecycle{Store: store, Audit: func(firewall.FirewallAction) error { return nil }}
			k := &retiringKernel{proven: mode == "retired", at: time.Now().UTC()}
			err := l.Recover(k)
			wantReads, wantProofs := 1, 1
			switch mode {
			case "retired":
				wantReads = 2
			case "no pending":
				wantProofs = 0
			}
			if mode == "not proven" && !errors.Is(err, firewall.ErrActionUnknown) || mode != "not proven" && err != nil {
				t.Fatalf("recovery outcome: %v", err)
			}
			if store.reads != wantReads || k.calls != wantProofs || k.writes != 0 {
				t.Fatalf("recovery order: audit reads %d, proofs %d, writes %d", store.reads, k.calls, k.writes)
			}
		})
	}
}
