package admissionowner

import (
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/store"
)

// A blocked independent stop notification is pending work before delivery returns.
func TestOwnerBlockedStopNoticeReportsQueueHealth(t *testing.T) {
	f := newOwnerFixture(t)
	f.host.set(func(h *fakeHost) { h.clockErr = errors.New("clock unavailable") })
	entered, release := make(chan struct{}), make(chan struct{})
	releaseDelivery := sync.OnceFunc(func() { close(release) })
	defer releaseDelivery()
	opts := f.options()
	opts.NoticeEvery = time.Millisecond
	opts.Deliver = func([]alert.Finding) error { close(entered); <-release; return nil }
	o := f.start(opts)
	<-entered
	if q := o.QueueStatuses(time.Now().Add(2 * time.Minute))["notices"]; q.Depth != 1 || q.Reason != "consumer_stalled" {
		t.Fatalf("blocked stop notification is invisible: %+v", q)
	}
	releaseDelivery()
	o.Stop()
	if q := o.QueueStatuses(time.Now().Add(2 * time.Minute))["notices"]; q.Depth != 0 || q.Status == "degraded" {
		t.Fatalf("delivered stop notification did not recover: %+v", q)
	}
}

// Delivery is unfinished until its ledger acknowledgement succeeds.
func TestOwnerNoticeAckFailureReportsQueueHealth(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	sink := &noticeSink{}
	opts := f.options()
	opts.Deliver = sink.deliver
	o := f.start(opts)
	criticalGap(t, o, p, f.host)
	prev := ackNotices
	ackNotices = func(*store.AdmissionLedger, []admission.NoticeAck) error { return errors.New("ledger unavailable") }
	t.Cleanup(func() { ackNotices = prev })
	o.notices.cycle()
	if q := o.QueueStatuses(time.Now().Add(2 * time.Minute))["notices"]; q.Depth != 2 || q.Reason != "consumer_stalled" {
		t.Fatalf("unacknowledged notices are invisible: %+v", q)
	}
	ackNotices = prev
	o.notices.cycle()
	if sink.count() != 1 {
		t.Fatalf("ack retry repeated delivery: %d deliveries", sink.count())
	}
	if q := o.QueueStatuses(time.Now().Add(2 * time.Minute))["notices"]; q.Depth != 0 || q.Status == "degraded" {
		t.Fatalf("acknowledgement did not recover queue health: %+v", q)
	}
}

// A failed stop notification remains pending even after admission recovers.
func TestOwnerRetriesStopNoticeAfterRecovery(t *testing.T) {
	f := newOwnerFixture(t)
	sink := &noticeSink{err: errors.New("delivery unavailable")}
	opts := f.options()
	opts.Deliver = sink.deliver
	o := f.start(opts)
	f.host.set(func(h *fakeHost) { h.clockErr = errors.New("clock unavailable") })
	if err := o.do(o.tick); err == nil {
		t.Fatal("failed clock reading succeeded")
	}
	o.notices.cycle()
	f.host.set(func(h *fakeHost) { h.clockErr = nil })
	if err := o.do(o.tick); err != nil {
		t.Fatal(err)
	}
	sink.set(nil)
	o.notices.cycle()
	o.notices.cycle()
	if sink.count() != 2 || len(sink.last()) != 1 || !strings.Contains(sink.last()[0].Details, "clock unavailable") {
		t.Fatalf("recovery discarded the failed stop notification: %d deliveries", sink.count())
	}
	if q := o.QueueStatuses(time.Now().Add(2 * time.Minute))["notices"]; q.Depth != 0 || q.Status == "degraded" {
		t.Fatalf("retried notification did not recover queue health: %+v", q)
	}
}
