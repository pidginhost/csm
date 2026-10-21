package admissionowner

import (
	"errors"
	"testing"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/store"
)

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
