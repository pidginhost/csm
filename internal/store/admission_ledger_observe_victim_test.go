package store

import (
	"reflect"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
)

// A preview reports the block whose slot it would take, here an import,
// and still claims nothing; a preview into a free slot and a readback of
// a reservation report none.
func TestAdmissionLedgerObserveReportsItsVictim(t *testing.T) {
	f := liveLedgerFixture(t)
	imp := f.importAt(1, "192.0.2.60", time.Hour)
	f.fillGeneral(1, imp)
	expires := f.wall.Add(time.Hour)
	id := f.queuedWith("192.0.2.11", admission.SeverityCritical)
	if _, _, granted, victim, err := f.l.ObserveVictim(id, admission.LaneGeneral, expires); err != nil || !granted || victim != imp {
		t.Fatalf("funded preview = %t %+v %v, want the import", granted, victim, err)
	}
	if pool := f.pool([]admission.EvictionVictim{imp}); len(pool) != 1 || len(f.intents()) != 0 {
		t.Fatalf("the preview claimed its victim: %+v", pool)
	}
	f.fillGeneral(2, imp)
	id = f.queuedWith("192.0.2.12", admission.SeverityCritical)
	if _, _, granted, victim, err := f.l.ObserveVictim(id, admission.LaneGeneral, expires); err != nil || !granted || victim != (admission.EvictionVictim{}) {
		t.Fatalf("free-slot preview = %t %+v %v", granted, victim, err)
	}
	f.fillGeneral(1, imp)
	id = f.queuedWith("192.0.2.13", admission.SeverityCritical)
	_, reserved, granted, err := f.l.Reserve(id, admission.LaneGeneral, expires)
	if err != nil || !granted {
		t.Fatalf("reservation = %+v %t %v", reserved, granted, err)
	}
	if rec, ok := f.effectOf(reserved); !ok || rec.Victim != (admission.EffectRef{Action: imp.Action, ExpiresAt: imp.ExpiresAt}) {
		t.Fatalf("reservation lost its victim: %+v (%t)", rec, ok)
	}
	before := f.snapshot()
	if c, a, granted, victim, err := f.l.ObserveVictim(id, admission.LaneGeneral, expires); err != nil || granted || victim != (admission.EvictionVictim{}) || a != reserved || c.State != admission.StateReserved {
		t.Fatalf("readback = %t %+v %v, candidate %+v, attempt %+v", granted, victim, err, c, a)
	}
	if !reflect.DeepEqual(before, f.snapshot()) {
		t.Fatal("preview readback changed the held reservation")
	}
}

// A failed preview transaction reports no replacement and leaves the
// candidate, charges and victim available for a later committed preview.
func TestAdmissionLedgerObserveVictimFailureIsAtomic(t *testing.T) {
	f := liveLedgerFixture(t)
	imp := f.importAt(1, "192.0.2.60", time.Hour)
	f.fillGeneral(1, imp)
	id := f.queuedWith("192.0.2.11", admission.SeverityCritical)
	before := f.snapshot()
	f.failNext("observe")
	if _, _, granted, victim, err := f.l.ObserveVictim(id, admission.LaneGeneral, f.wall.Add(time.Hour)); err == nil || granted || victim != (admission.EvictionVictim{}) {
		t.Fatalf("failed preview reported a replacement: %t %+v %v", granted, victim, err)
	}
	if !reflect.DeepEqual(before, f.snapshot()) {
		t.Fatal("failed preview changed the ledger")
	}
	if _, _, granted, victim, err := f.l.ObserveVictim(id, admission.LaneGeneral, f.wall.Add(time.Hour)); err != nil || !granted || victim != imp {
		t.Fatalf("preview retry = %t %+v %v", granted, victim, err)
	}
}
