package store

import (
	"reflect"
	"runtime"
	"runtime/debug"
	"runtime/metrics"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	bolt "go.etcd.io/bbolt"
)

// A retained window can contain ordinary charges whose attempt history
// retired after a reboot. Reading their import status must keep temporary
// classification memory bounded while visiting distinct timestamps.
func TestAdmissionLedgerImportedSpendBoundsTemporaryMemory(t *testing.T) {
	f := newLedgerFixture(t)
	const charges = 4096
	if err := f.db.bolt.Update(func(tx *bolt.Tx) error {
		for seq := uint32(1); seq <= charges; seq++ {
			charge := f.ledgerCharge(f.wall.Add(time.Duration(seq)*time.Nanosecond), seq, admission.LaneGeneral, 0)
			if err := putCharge(tx, charge, true); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	before := f.snapshot()
	previousGC := debug.SetGCPercent(20)
	t.Cleanup(func() { debug.SetGCPercent(previousGC) })
	samples := []metrics.Sample{{Name: "/gc/heap/live:bytes"}}
	runtime.GC()
	metrics.Read(samples)
	baseline := samples[0].Value.Uint64()
	got, err := f.l.ImportedLegacySpend()
	metrics.Read(samples)
	live := samples[0].Value.Uint64()
	if err != nil || got != (admission.LegacySpend{}) {
		t.Fatalf("ordinary retained charges returned %+v, %v", got, err)
	}
	// The latest completed collection measures live memory during the
	// read, before the temporary classification data becomes unreachable.
	if live > baseline+(32<<20) {
		t.Fatalf("temporary import classification retained %d bytes above baseline", live-baseline)
	}
	if after := f.snapshot(); !reflect.DeepEqual(after, before) {
		t.Fatal("reading retained charges changed the ledger")
	}
}
