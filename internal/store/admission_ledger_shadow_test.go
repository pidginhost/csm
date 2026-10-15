package store

import (
	"reflect"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
)

// A forecast starts from the committed ceiling and the charges it retains,
// read together and proven against each other, without a write.
func TestAdmissionLedgerCeilingSnapshot(t *testing.T) {
	f := newLedgerFixture(t)
	f.admitted(time.Hour)
	f.admitted(time.Hour)
	before := f.snapshot()
	c, charges, err := f.l.CeilingSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(c, f.ceilingState()) || !reflect.DeepEqual(charges, f.charges()) || len(charges) != 2 || c.General.Used != 2 {
		t.Fatalf("snapshot = %+v with %d charges", c, len(charges))
	}
	if !reflect.DeepEqual(before, f.snapshot()) {
		t.Fatal("a snapshot changed the ledger")
	}
	if err = f.db.bolt.Update(func(tx *bolt.Tx) error {
		cur := tx.Bucket([]byte(admissionChargesBucket)).Cursor()
		k, _ := cur.First()
		return tx.Bucket([]byte(admissionChargesBucket)).Delete(k)
	}); err != nil {
		t.Fatal(err)
	}
	if _, _, err = f.l.CeilingSnapshot(); !isCorrupt(err) {
		t.Fatalf("charges that disagree with usage: %v", err)
	}
}
