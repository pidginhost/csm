package store

import (
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	bolt "go.etcd.io/bbolt"
)

// The daemon reads the saved admission clock before the owner opens the
// ledger; a database without a ledger has none.
func TestReadAdmissionClockReturnsTheSavedClock(t *testing.T) {
	empty := openTestDB(t)
	if c, err := ReadAdmissionClock(empty); err != nil || c.Initialized() {
		t.Fatalf("without a ledger: %+v, %v", c, err)
	}
	f := newLedgerFixture(t)
	f.tickAt(ledgerT0.Add(time.Minute))
	c, err := ReadAdmissionClock(f.db)
	if err != nil || !c.Now().Equal(ledgerT0.Add(time.Minute)) {
		t.Fatalf("saved clock %v, %v", c.Now(), err)
	}
	r := admission.ClockReading{Wall: ledgerT0, BootID: ledgerBoot, SinceBoot: f.since + time.Minute}
	if got := c.Proven(r); !got.Equal(ledgerT0.Add(2 * time.Minute)) {
		t.Fatalf("proven after a minute on the same boot = %v", got)
	}
}

func TestReadAdmissionClockRejectsDamagedCheckpoints(t *testing.T) {
	for _, mode := range []string{"checksum", "missing", "schema", "closed"} {
		t.Run(mode, func(t *testing.T) {
			f := newLedgerFixture(t)
			if mode == "closed" {
				if err := f.db.Close(); err != nil {
					t.Fatal(err)
				}
			} else if err := f.db.bolt.Update(func(tx *bolt.Tx) error {
				meta := tx.Bucket([]byte(admissionMetaBucket))
				switch mode {
				case "missing":
					return meta.Delete(admissionClockKey)
				case "schema":
					return meta.Put(admissionSchemaKey, []byte{255})
				default:
					data := append([]byte(nil), meta.Get(admissionClockKey)...)
					data[len(data)-1] ^= 1
					return meta.Put(admissionClockKey, data)
				}
			}); err != nil {
				t.Fatal(err)
			}
			clock, err := ReadAdmissionClock(f.db)
			if err == nil || clock.Initialized() {
				t.Fatalf("damaged checkpoint became a floor: initialized=%t err=%v", clock.Initialized(), err)
			}
		})
	}
}
