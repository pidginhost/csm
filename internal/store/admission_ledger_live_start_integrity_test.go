package store

import (
	"reflect"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	bolt "go.etcd.io/bbolt"
)

// A schema that has started cannot lose its marker and become eligible
// again, even through a handle opened before the start.
func TestAdmissionLedgerLiveStartMissingMarkerRefuses(t *testing.T) {
	f := newLedgerFixture(t)
	stale, err := OpenAdmissionLedger(f.db, f.reg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = stale.Tick(admission.ClockReading{Wall: f.wall, BootID: ledgerBoot, SinceBoot: f.since}); err != nil {
		t.Fatal(err)
	}
	if err = f.l.StartLive(admission.LegacyHandover{}); err != nil {
		t.Fatal(err)
	}
	if err = f.db.bolt.Update(func(tx *bolt.Tx) error { return tx.Bucket([]byte(admissionQueueStateBucket)).Delete(liveStartKey) }); err != nil {
		t.Fatal(err)
	}
	before := f.snapshot()
	if _, err = OpenAdmissionLedger(f.db, f.reg); !isCorrupt(err) {
		t.Errorf("opened a live schema without its marker: %v", err)
	}
	if err = stale.StartLive(admission.LegacyHandover{Pending: 2}); !isCorrupt(err) {
		t.Errorf("stale handle restarted a damaged live schema: %v", err)
	}
	if !reflect.DeepEqual(before, f.snapshot()) {
		t.Fatal("damaged marker changed durable state")
	}
}

// The greater-of balance is a migration balance, including the preview
// units it reused. A later forecast cannot refund those known legacy units.
func TestAdmissionLedgerLiveStartForecastKeepsCarriedSpend(t *testing.T) {
	f := newLedgerFixture(t)
	f.begin()
	f.observedArrival("192.0.2.10", "offset=1")
	end := f.wall.Add(30 * time.Minute)
	if err := f.l.StartLive(admission.LegacyHandover{Spend: admission.LegacySpend{Units: 9, At: end}}); err != nil {
		t.Fatal(err)
	}
	before := f.snapshot()
	seed, kept, err := f.l.ForecastSeed()
	if err != nil {
		t.Fatal(err)
	}
	var units uint32
	for _, c := range kept {
		units += c.Cost
	}
	if units != 9 || seed.General.Used != 9 || seed != f.ceilingState() {
		t.Fatalf("forecast lost carried spend: units=%d seed=%+v", units, seed)
	}
	if !reflect.DeepEqual(before, f.snapshot()) {
		t.Fatal("forecast changed durable state")
	}
	// A preview created after the marker is still comparison work, even
	// when the admission clock has not moved since the live start.
	f.observedArrival("192.0.2.11", "offset=1")
	seed, _, err = f.l.ForecastSeed()
	if err != nil || seed.General.Used != 9 {
		t.Fatalf("later preview entered the forecast: %+v, %v", seed, err)
	}
	if got, err := f.l.ImportedLegacySpend(); err != nil || got.Units != 0 {
		t.Fatalf("handover masquerades as first import: %+v, %v", got, err)
	}
	if _, err := OpenAdmissionLedger(f.db, f.reg); err != nil {
		t.Fatal(err)
	}
}
