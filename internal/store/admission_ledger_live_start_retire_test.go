package store

import (
	"math"
	"reflect"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	bolt "go.etcd.io/bbolt"
)

// Released is not permission to discard a genuine attempt, even if the
// damage appears after open and the index matches the forged history row.
func TestAdmissionLedgerReleasedHistoryMutationPathsRefuse(t *testing.T) {
	for _, mode := range []string{"pressure", "target", "audit"} {
		t.Run(mode, func(t *testing.T) {
			f := newLedgerFixture(t)
			id := f.applied(time.Hour)
			if mode != "audit" {
				f.ackAll()
			}
			if err := f.l.StartLive(admission.LegacyHandover{}); err != nil {
				t.Fatal(err)
			}
			if err := f.db.bolt.Update(func(tx *bolt.Tx) error {
				h, _, err := loadHistoryEntry(tx, id)
				if err != nil {
					return err
				}
				keys, err := h.RetireKeys(id)
				if err != nil {
					return err
				}
				for _, k := range keys {
					if err = tx.Bucket([]byte(admissionRetireBucket)).Delete(k); err != nil {
						return err
					}
				}
				h.Released, h.Eligible = true, h.Ended
				raw, err := h.MarshalBinary()
				if err != nil {
					return err
				}
				if err = tx.Bucket([]byte(admissionHistoryBucket)).Put([]byte(id), raw); err != nil {
					return err
				}
				if mode != "audit" {
					keys, err = h.RetireKeys(id)
					if err != nil {
						return err
					}
					for _, k := range keys {
						if err = tx.Bucket([]byte(admissionRetireBucket)).Put(k, nil); err != nil {
							return err
						}
					}
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			before := f.snapshot()
			var err error
			if mode == "audit" {
				var acks []admission.AuditAck
				for _, r := range f.pendingAudit() {
					acks = append(acks, r.Ack())
				}
				err = f.l.AckAudit(acks)
			} else {
				err = f.db.bolt.Update(func(tx *bolt.Tx) error {
					q, openErr := f.l.openQueue(tx, f.wall.Add(admission.HistoryTarget+time.Hour))
					if openErr != nil {
						return openErr
					}
					var retireErr error
					if mode == "pressure" {
						retireErr = q.retireForRoom(admission.LaneGeneral, math.MaxUint64)
					} else {
						retireErr = q.retireAtTarget()
					}
					if retireErr != nil {
						return retireErr
					}
					return q.flush()
				})
			}
			if !isCorrupt(err) {
				t.Fatalf("%s accepted genuine released history: %v", mode, err)
			}
			if !reflect.DeepEqual(before, f.snapshot()) {
				t.Fatal("refusal changed history, audit or accounting")
			}
		})
	}
}
