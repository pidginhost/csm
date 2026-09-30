package store

import (
	"reflect"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	bolt "go.etcd.io/bbolt"
)

// Each replacement is a valid row under its own key with unchanged slot
// totals. Open must still prove its link to the recorded attempt and intent.
func TestAdmissionLedgerAuditProofChecksIntent(t *testing.T) {
	for _, shape := range []string{
		"lane", "expiry", "kind", "target", "check", "finding", "roots",
		"reservation time", "execution before reservation", "execution at expiry",
		"execution after clock", "outcome time", "step order", "step gap", "step tier",
	} {
		t.Run(shape, func(t *testing.T) {
			f := newLedgerFixture(t)
			a := f.retried(2)
			f.tickAt(f.wall.Add(time.Second))
			if _, _, _, err := f.l.Execute(a.Attempt.ID); err != nil {
				t.Fatal(err)
			}
			if shape == "outcome time" {
				if _, _, err := f.l.Finish(a.Attempt.ID, admission.DispositionApplied); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := OpenAdmissionLedger(f.db, f.reg); err != nil {
				t.Fatalf("valid retry history refused: %v", err)
			}
			if err := f.db.bolt.Update(func(tx *bolt.Tx) error {
				var rows []admission.AuditRow
				for _, row := range f.pendingAuditIn(t, tx) {
					if row.Attempt.ID == a.Attempt.ID {
						rows = append(rows, row)
					}
				}
				row := rows[0]
				switch shape {
				case "lane":
					row.Lane = admission.LaneDirect
				case "expiry":
					row.ExpiresAt = row.ExpiresAt.Add(time.Second)
				case "kind":
					row.Kind = admission.KindPromote
				case "target":
					row.Target = f.target("192.0.2.11")
				case "check":
					row.Check = "reputation"
				case "finding":
					row.FindingID = "fedcba9876543210"
				case "roots":
					row.Roots = []admission.EvidenceID{"ev_ffffffffffffffffffffffffffffffff"}
				case "reservation time":
					row.At = row.At.Add(time.Second)
				case "execution before reservation":
					row = rows[1]
					row.At = a.Reserved.Add(-time.Nanosecond)
				case "execution at expiry":
					row = rows[1]
					row.At = a.ExpiresAt
				case "execution after clock":
					row = rows[1]
					row.At = f.wall.Add(time.Nanosecond)
				case "outcome time":
					row = rows[2]
					row.At = row.At.Add(-time.Nanosecond)
				case "step order":
					row.Transition, rows[1].Transition = rows[1].Transition, row.Transition
					if err := putAuditRowRaw(tx, rows[1], 0); err != nil {
						return err
					}
				case "step gap":
					if err := tx.Bucket([]byte(admissionOutboxBucket)).Delete(row.Key()); err != nil {
						return err
					}
					row.Transition--
				case "step tier":
					row.Tier = admission.Tier{Class: admission.ClassC3, Severity: admission.SeverityCritical}
				}
				return putAuditRowRaw(tx, row, 0)
			}); err != nil {
				t.Fatal(err)
			}
			before := f.snapshot()
			if _, err := OpenAdmissionLedger(f.db, f.reg); !isCorrupt(err) {
				t.Fatalf("accepted %s damage with balanced slots: %v", shape, err)
			}
			if !reflect.DeepEqual(before, f.snapshot()) {
				t.Fatal("refused open changed the ledger")
			}
		})
	}
}

func TestAdmissionLedgerNoticeProofRejectsFutureTimes(t *testing.T) {
	for _, shape := range []string{"event", "delivery"} {
		t.Run(shape, func(t *testing.T) {
			f := newLedgerFixture(t)
			if err := f.db.bolt.Update(func(tx *bolt.Tx) error {
				r, err := admission.NewNoticeRecord(criticalSummary).Add(f.wall, "", 0)
				if err != nil {
					return err
				}
				future := f.wall.Add(time.Second)
				if shape == "event" {
					r, err = r.Add(future, "", 0)
				} else {
					r, err = r.Ack(1, future)
				}
				if err != nil {
					return err
				}
				return putNoticeRecord(tx, r)
			}); err != nil {
				t.Fatal(err)
			}
			before := f.snapshot()
			if _, err := OpenAdmissionLedger(f.db, f.reg); !isCorrupt(err) {
				t.Fatalf("accepted notice %s after ledger clock: %v", shape, err)
			}
			if !reflect.DeepEqual(before, f.snapshot()) {
				t.Fatal("refused open changed the ledger")
			}
		})
	}
}

func TestAdmissionLedgerAuditProofOrdersAttempts(t *testing.T) {
	for _, shape := range []string{"duplicate transition", "later transition in earlier attempt"} {
		t.Run(shape, func(t *testing.T) {
			f := newLedgerFixture(t)
			a := f.retried(2)
			if _, _, _, err := f.l.Execute(a.Attempt.ID); err != nil {
				t.Fatal(err)
			}
			if _, _, err := f.l.Finish(a.Attempt.ID, admission.DispositionApplied); err != nil {
				t.Fatal(err)
			}
			var earlier, reserved admission.AuditRow
			var ack []admission.AuditID
			for _, row := range f.pendingAudit() {
				switch {
				case row.Attempt.Seq == 1 && row.State == admission.StateFailed:
					earlier = row
				case row.Attempt.Seq == 1 || row.State == admission.StateExecuting:
					ack = append(ack, row.ID())
				case row.State == admission.StateReserved:
					reserved = row
				}
			}
			if err := f.l.AckAudit(ack); err != nil {
				t.Fatal(err)
			}
			if _, err := OpenAdmissionLedger(f.db, f.reg); err != nil {
				t.Fatalf("valid partially acknowledged history refused: %v", err)
			}
			if err := f.db.bolt.Update(func(tx *bolt.Tx) error {
				if err := tx.Bucket([]byte(admissionOutboxBucket)).Delete(earlier.Key()); err != nil {
					return err
				}
				earlier.Transition = reserved.Transition
				if shape == "later transition in earlier attempt" {
					earlier.Transition++
				}
				return putAuditRowRaw(tx, earlier, 0)
			}); err != nil {
				t.Fatal(err)
			}
			before := f.snapshot()
			if _, err := OpenAdmissionLedger(f.db, f.reg); !isCorrupt(err) {
				t.Fatalf("accepted %s with balanced slots: %v", shape, err)
			}
			if !reflect.DeepEqual(before, f.snapshot()) {
				t.Fatal("refused open changed the ledger")
			}
		})
	}
}
