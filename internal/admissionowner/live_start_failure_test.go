package admissionowner

import (
	"errors"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/store"
)

// A failed live-start transaction must not replace the status of the
// committed import with a read error from the abandoned handover.
func TestOwnerLiveStartImportErrorRequiresCommit(t *testing.T) {
	f := newOwnerFixture(t)
	f.legacy(`{"blocks_this_hour":3,"hour_key":"2026-10-04T12"}`)
	o, r, _ := policyOwner(t, f, newFakeBlocks(), dryPolicy(1))
	f.legacy(`{"blocks_this_hour":3}`)
	fail := true
	setOwnerHook(t, o, &startLiveLedger, func(l *store.AdmissionLedger, h admission.LegacyHandover) error {
		if fail {
			return errors.New("live start unavailable")
		}
		return l.StartLive(h)
	})
	r.publish(validPolicy(2))
	if err := o.Reload(); err == nil || liveStarted(t, o) {
		t.Fatalf("failed live start = %v", err)
	}
	if imp := o.Status().Owner.Import; imp == nil || imp.Units != 3 || imp.Error != "" {
		t.Errorf("uncommitted handover replaced the import: %+v", imp)
	}
	f.legacy(`{"blocks_this_hour":5,"hour_key":"2026-10-04T12"}`)
	fail = false
	if err := o.Reload(); err != nil {
		t.Fatal(err)
	}
	if !liveStarted(t, o) || ceiling(t, o).General.Used != 5 {
		t.Fatal("retry did not commit the repaired handover")
	}
	if imp := o.Status().Owner.Import; imp == nil || imp.Units != 3 || imp.Error != "" {
		t.Errorf("successful handover retained an abandoned read error: %+v", imp)
	}
}

// Once the live start commits without saved credit, its read error must
// survive retries of later startup steps on the same owner.
func TestOwnerLiveStartImportErrorSurvivesStartupRetry(t *testing.T) {
	f := newOwnerFixture(t)
	f.legacy(`{"blocks_this_hour":3,"hour_key":"2026-10-04T12"}`)
	o, _, _ := policyOwner(t, f, newFakeBlocks(), dryPolicy(1))
	o.Stop()
	f.legacy(`{"blocks_this_hour":3}`)
	previous := readSnapshot
	reads := 0
	readSnapshot = func(l *store.AdmissionLedger) (*admission.QueueSnapshot, error) {
		reads++
		if reads == 1 {
			return nil, errors.New("snapshot unavailable")
		}
		return previous(l)
	}
	t.Cleanup(func() { readSnapshot = previous })
	o, _, _ = policyOwner(t, f, newFakeBlocks(), validPolicy(1))
	imp := o.Status().Owner.Import
	if ownerStarted(t, o) || !liveStarted(t, o) || imp == nil || imp.Error == "" {
		t.Fatal("fixture did not commit an unknown handover before failing startup")
	}
	if err := o.do(func() error {
		o.startErr = o.start()
		o.refreshStatus()
		return o.startErr
	}); err != nil {
		t.Fatal(err)
	}
	if !ownerStarted(t, o) {
		t.Fatal("startup retry did not finish")
	}
	if c := ceiling(t, o); c.General.Credit != 0 || c.Reserved.Credit != 0 || c.General.Used != 3 {
		t.Fatalf("retry changed the committed handover: %+v", c)
	}
	if got := o.Status().Owner.Import; got == nil || *got != *imp {
		t.Fatalf("startup retry changed the committed read error: %+v, want %+v", got, imp)
	}
}

// A failed live start is a failed tick even when no drain or schedule
// runs. Status and the independent stop notice must name that failure.
func TestOwnerLiveStartTickFailureIsVisibleUntilRecovery(t *testing.T) {
	f := newOwnerFixture(t)
	sink := &noticeSink{}
	o, r := noticeOwner(t, f, dryPolicy(1), sink)
	fail := true
	setOwnerHook(t, o, &startLiveLedger, func(l *store.AdmissionLedger, h admission.LegacyHandover) error {
		if fail {
			return errors.New("live start unavailable")
		}
		return l.StartLive(h)
	})
	r.publish(validPolicy(2))
	if err := o.do(func() error {
		if err := o.refreshPolicy(); err != nil {
			return err
		}
		return o.tick()
	}); err == nil {
		t.Fatal("failed live start did not fail the tick")
	}
	if st := o.Status(); st.Ingress.Admitting || !strings.Contains(st.Owner.TickError, "live start unavailable") {
		t.Errorf("cached status hides the failed live start: %+v %+v", st.Ingress, st.Owner)
	}
	if err := o.do(func() error { o.refreshInventory(); return nil }); err != nil {
		t.Fatal(err)
	}
	if o.ingress.Health().Admitting {
		t.Error("inventory admitted work before live start recovery")
	}
	o.notices.cycle()
	if n := sink.count(); n != 1 {
		t.Fatalf("stop deliveries = %d, want one", n)
	}
	if fs := sink.last(); len(fs) != 1 || !strings.Contains(fs[0].Details, "live start unavailable") {
		t.Errorf("stop notice did not name the failed live start: %+v", fs)
	}
	fail = false
	if err := o.do(o.tick); err != nil {
		t.Fatal(err)
	}
	if st := o.Status(); !liveStarted(t, o) || !st.Ingress.Admitting || st.Owner.TickError != "" {
		t.Fatalf("successful retry did not clear the hold: %+v %+v", st.Ingress, st.Owner)
	}
}
