package store

import (
	"math"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	bolt "go.etcd.io/bbolt"
)

// Design C7: observe previews carry no review or undo, so the live start
// makes their history eligible at once, and pressure retires it before any
// genuine history. A preview whose audit rows still wait gets its keys at
// the released time once they are acknowledged. Ended genuine history and
// history that already left its review window keep their times. A reopened
// ledger proves the released times.
func TestAdmissionLedgerLiveStartReleasesPreviewHistory(t *testing.T) {
	f := newLedgerFixture(t)
	f.begin()
	old, _ := f.observedArrival("192.0.2.12", "offset=1")
	f.ackAll()
	f.tickAt(f.wall.Add(admission.HistoryRetention))
	acked, _ := f.observedArrival("192.0.2.10", "offset=1")
	applied := f.applied(time.Hour)
	f.ackAll()
	waiting, _ := f.observedArrival("192.0.2.11", "offset=1")
	f.tickAt(f.wall.Add(time.Minute))
	start := f.wall
	kept := map[admission.CandidateID]admission.HistoryEntry{}
	for _, id := range []admission.CandidateID{old, applied} {
		kept[id], _ = f.historyEntry(id)
	}
	if err := f.l.StartLive(admission.LegacyHandover{}); err != nil {
		t.Fatal(err)
	}
	for _, id := range []admission.CandidateID{acked, waiting} {
		if h, found := f.historyEntry(id); !found || !h.Released || !h.Eligible.Equal(start) {
			t.Fatalf("preview history %s = %+v (found %v), want released at %v", id, h, found, start)
		}
	}
	for id, want := range kept {
		if h, _ := f.historyEntry(id); h != want {
			t.Fatalf("history %s = %+v, want %+v kept", id, h, want)
		}
	}
	keyOf := func(id admission.CandidateID) string {
		h, _ := f.historyEntry(id)
		keys, err := h.RetireKeys(id)
		if err != nil {
			t.Fatal(err)
		}
		return string(keys[0])
	}
	if keys := retireKeysIn(t, f.db); !keys[keyOf(acked)] || keys[keyOf(waiting)] {
		t.Fatalf("retire keys = %v", keys)
	}
	if _, err := OpenAdmissionLedger(f.db, f.reg); err != nil {
		t.Fatalf("reopening released history: %v", err)
	}
	f.ackAll()
	if keys := retireKeysIn(t, f.db); !keys[keyOf(waiting)] {
		t.Fatal("acknowledged preview history got no released key")
	}
	if err := f.db.bolt.Update(func(tx *bolt.Tx) error {
		q, err := f.l.openQueue(tx, f.wall)
		if err != nil {
			return err
		}
		if err = q.retireForRoom(admission.LaneGeneral, math.MaxUint64); err != nil {
			return err
		}
		return q.flush()
	}); err != nil {
		t.Fatal(err)
	}
	for id, want := range map[admission.CandidateID]bool{old: false, acked: false, waiting: false, applied: true} {
		if _, found := f.historyEntry(id); found != want {
			t.Errorf("history %s kept %v under pressure, want %v", id, found, want)
		}
	}
}

// Opening proves a released time: only a preview's history may be
// released, only at the live start, and only at its time.
func TestAdmissionLedgerReleasedHistoryRefusesDamage(t *testing.T) {
	for _, damage := range []string{"genuine history", "another time", "no live start"} {
		t.Run(damage, func(t *testing.T) {
			f := newLedgerFixture(t)
			f.begin()
			preview, _ := f.observedArrival("192.0.2.10", "offset=1")
			applied := f.applied(time.Hour)
			f.ackAll()
			if err := f.l.StartLive(admission.LegacyHandover{}); err != nil {
				t.Fatal(err)
			}
			if err := f.db.bolt.Update(func(tx *bolt.Tx) error {
				id := preview
				h, _, err := loadHistoryEntry(tx, id)
				if err != nil {
					return err
				}
				switch damage {
				case "genuine history":
					id = applied
					if h, _, err = loadHistoryEntry(tx, id); err != nil {
						return err
					}
					h.Released, h.Eligible = true, h.Ended
				case "another time":
					h.Eligible = h.Eligible.Add(time.Nanosecond)
				case "no live start":
					if err = tx.Bucket([]byte(admissionQueueStateBucket)).Delete(liveStartKey); err != nil {
						return err
					}
				}
				// Keep the index in step: only the released time may be wrong.
				old, _, err := loadHistoryEntry(tx, id)
				if err != nil {
					return err
				}
				keys, err := retireKeysOf(tx, id, old)
				if err != nil {
					return err
				}
				for _, k := range keys {
					if err = tx.Bucket([]byte(admissionRetireBucket)).Delete(k); err != nil {
						return err
					}
				}
				return putHistoryEntry(tx, id, h)
			}); err != nil {
				t.Fatal(err)
			}
			if _, err := OpenAdmissionLedger(f.db, f.reg); !isCorrupt(err) {
				t.Fatalf("opened damaged released history: %v", err)
			}
		})
	}
}
