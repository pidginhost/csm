package admissionowner

import (
	"errors"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/store"
)

// A live start also ends the wait of failing live deliveries: the first
// live alert after the start goes out at once. Live records before the
// start come from a live period whose start failed.
func TestOwnerLiveStartEndsTheLiveNoticeBackoff(t *testing.T) {
	clock := &testClock{t: time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)}
	previous := deliveryNow
	deliveryNow = clock.now
	t.Cleanup(func() { deliveryNow = previous })
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	sink := &noticeSink{}
	o, r := noticeOwner(t, f, dryPolicy(1), sink)
	fail := true
	setOwnerHook(t, o, &startLiveLedger, func(l *store.AdmissionLedger, h admission.LegacyHandover) error {
		if fail {
			return errors.New("ledger busy")
		}
		return l.StartLive(h)
	})
	terminate := func(ip string) {
		t.Helper()
		id, _ := queuedAt(t, o, p, f.host, admission.SeverityCritical, ip)
		if err := o.do(func() error { _, err := o.ledger.Terminate(id, admission.ReasonPolicy); return err }); err != nil {
			t.Fatal(err)
		}
	}
	r.publish(validPolicy(2))
	if err := o.Reload(); err == nil {
		t.Fatal("a failed live start did not fail the reload")
	}
	terminate("192.0.2.10")
	r.publish(dryPolicy(3))
	if err := o.Reload(); err != nil {
		t.Fatal(err)
	}
	sink.set(errors.New("alert channel down"))
	for range 4 {
		o.notices.cycle()
	}
	if n := ledgerDeliveries(sink); n != 3 || sink.lastPreview() {
		t.Fatalf("failing live deliveries = %d, preview %v; want 3 live before the wait", n, sink.lastPreview())
	}
	sink.set(nil)
	fail = false
	r.publish(validPolicy(4))
	if err := o.Reload(); err != nil {
		t.Fatal(err)
	}
	terminate("192.0.2.11")
	o.notices.cycle()
	if n := ledgerDeliveries(sink); n != 4 || sink.lastPreview() {
		t.Fatalf("a live alert after the live start waited: %d deliveries, preview %v; want 4, live", n, sink.lastPreview())
	}
}
