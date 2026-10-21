package admissionowner

import (
	"errors"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/store"
)

// A preview delivery failure must not postpone the first live gap. The
// new notice stream keeps its own retry delay after the live start.
func TestOwnerLiveStartResetsPreviewNoticeRetry(t *testing.T) {
	clock := &testClock{t: time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)}
	previous := deliveryNow
	deliveryNow = clock.now
	t.Cleanup(func() { deliveryNow = previous })
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	sink := &noticeSink{err: errors.New("preview history unavailable")}
	o, r := noticeOwner(t, f, dryPolicy(1), sink)
	criticalGap(t, o, p, f.host)
	for range 3 {
		o.notices.cycle()
	}
	o.notices.cycle()
	if n := ledgerDeliveries(sink); n != 3 || !sink.lastPreview() {
		t.Fatalf("preview retry was not delayed: %d deliveries", n)
	}
	r.publish(validPolicy(2))
	if err := o.Reload(); err != nil {
		t.Fatal(err)
	}
	id, _ := queuedAt(t, o, p, f.host, admission.SeverityCritical, "192.0.2.11")
	if err := o.do(func() error { _, err := o.ledger.Terminate(id, admission.ReasonPolicy); return err }); err != nil {
		t.Fatal(err)
	}
	// Live delivery can still fail; its first attempts must start promptly,
	// then retain their own backoff on later cycles.
	for range 3 {
		o.notices.cycle()
	}
	if n := ledgerDeliveries(sink); n != 6 || sink.lastPreview() {
		t.Fatalf("preview retry postponed live notices: %d deliveries, want 6", n)
	}
	sink.set(nil)
	o.notices.cycle()
	if n := ledgerDeliveries(sink); n != 6 {
		t.Fatalf("live retry delay was reset again: %d deliveries", n)
	}
	clock.advance(2 * defaultNoticeEvery)
	o.notices.cycle()
	if n := ledgerDeliveries(sink); n != 7 || sink.lastPreview() {
		t.Fatalf("live retry did not deliver: %d deliveries", n)
	}
}

// A preview receipt must not acknowledge a new live gap with the same key
// and first timestamp after StartLive cleared the preview records.
func TestOwnerLiveStartDiscardsOldNoticeReceipt(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	sink := &noticeSink{}
	o, r := noticeOwner(t, f, dryPolicy(1), sink)
	criticalGap(t, o, p, f.host)
	fail := true
	setOwnerHook(t, o, &ackNotices, func(l *store.AdmissionLedger, acks []admission.NoticeAck) error {
		if fail {
			return errors.New("fixture acknowledgement failure")
		}
		return l.AckNotices(acks)
	})
	o.notices.cycle()
	if ledgerDeliveries(sink) != 1 || !sink.lastPreview() {
		t.Fatal("preview delivery missing")
	}
	r.publish(validPolicy(2))
	if err := o.Reload(); err != nil {
		t.Fatal(err)
	}
	id, _ := queuedAt(t, o, p, f.host, admission.SeverityCritical, "192.0.2.11")
	if err := o.do(func() error { _, err := o.ledger.Terminate(id, admission.ReasonPolicy); return err }); err != nil {
		t.Fatal(err)
	}
	fail = false
	o.notices.cycle()
	if ledgerDeliveries(sink) != 2 || sink.lastPreview() {
		t.Fatal("old preview receipt consumed the first live notice")
	}
}
