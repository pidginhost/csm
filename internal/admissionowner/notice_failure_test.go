package admissionowner

import (
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
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

// A channel that keeps failing is not sent the same notice every cycle,
// which would repeat it on every channel that did accept it and in
// history: the next two cycles retry at once, each later attempt waits
// twice as long as the one before, up to an hour, and a delivery restores
// prompt retries.
func TestOwnerBacksOffAFailingNoticeChannel(t *testing.T) {
	prev := deliveryNow
	t.Cleanup(func() { deliveryNow = prev })
	start := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	now := start
	deliveryNow = func() time.Time { return now }
	f := newOwnerFixture(t)
	sink := &noticeSink{err: errors.New("mail relay down")}
	opts := f.options()
	opts.Deliver = sink.deliver
	o := f.start(opts)
	f.host.set(func(h *fakeHost) { h.clockErr = errors.New("clock unavailable") })
	_ = o.do(o.tick)
	var attempts []time.Duration
	for range 2 * 720 {
		before := sink.count()
		o.notices.cycle()
		if sink.count() != before {
			attempts = append(attempts, now.Sub(start))
		}
		now = now.Add(5 * time.Second)
	}
	var want []time.Duration
	for _, s := range []int{0, 5, 10, 20, 40, 80, 160, 320, 640, 1280, 2560, 5120} {
		want = append(want, time.Duration(s)*time.Second)
	}
	if !reflect.DeepEqual(attempts, want) {
		t.Fatalf("attempts over two hours at %v, want %v", attempts, want)
	}
	sink.set(nil)
	now = start.Add(8720 * time.Second)
	o.notices.cycle()
	if sink.count() != len(want)+1 {
		t.Fatalf("the hour-late retry did not deliver: %d attempts", sink.count())
	}
	f.host.set(func(h *fakeHost) { h.clockErr = nil })
	if err := o.do(o.tick); err != nil {
		t.Fatal(err)
	}
	sink.set(errors.New("mail relay down"))
	f.host.set(func(h *fakeHost) { h.clockErr = errors.New("clock unavailable") })
	_ = o.do(o.tick)
	before := sink.count()
	for range 4 {
		o.notices.cycle()
	}
	if got := sink.count() - before; got != 3 {
		t.Fatalf("a new stop after a delivery made %d attempts in four cycles, want 3", got)
	}
}

// A ledger delivery outage cannot delay the independent alert about a new
// admission outage, and delivering that alert must not restart ledger retries.
func TestOwnerStopNoticeDoesNotWaitForLedgerRetry(t *testing.T) {
	prev := deliveryNow
	t.Cleanup(func() { deliveryNow = prev })
	now := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	deliveryNow = func() time.Time { return now }
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	sink := &noticeSink{err: errors.New("delivery unavailable")}
	opts := f.options()
	opts.Deliver = sink.deliver
	o := f.start(opts)
	criticalGap(t, o, p, f.host)
	for range 3 {
		o.notices.cycle()
	}
	if sink.count() != 3 {
		t.Fatalf("ledger delivery attempts = %d, want 3", sink.count())
	}
	sink.set(nil)
	f.host.set(func(h *fakeHost) { h.clockErr = errors.New("clock unavailable") })
	if err := o.do(o.tick); err == nil {
		t.Fatal("failed clock reading succeeded")
	}
	o.notices.cycle()
	if sink.count() != 4 || len(sink.last()) != 1 || !strings.Contains(sink.last()[0].Message, "admission stopped") {
		t.Fatalf("ledger backoff hid or repeated the stop alert: %d deliveries", sink.count())
	}
	if q := o.QueueStatuses(now.Add(2 * time.Minute))["notices"]; q.Depth != 2 || q.Reason != "consumer_stalled" {
		t.Fatalf("ledger backoff lost queue health after the stop delivery: %+v", q)
	}
	now = now.Add(10 * time.Second)
	o.notices.cycle()
	if sink.count() != 5 || len(sink.last()) != 2 {
		t.Fatalf("scheduled ledger retry did not deliver: %d deliveries", sink.count())
	}
	if q := o.QueueStatuses(now)["notices"]; q.Depth != 0 || q.Status == "degraded" {
		t.Fatalf("delivered ledger notices did not recover queue health: %+v", q)
	}
}

// A pending stop alert survives recovery, without deferring new ledger
// notices or losing its own retry schedule when those notices are delivered.
func TestOwnerLedgerNoticesDoNotWaitForStopRetry(t *testing.T) {
	prev := deliveryNow
	t.Cleanup(func() { deliveryNow = prev })
	now := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	deliveryNow = func() time.Time { return now }
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	sink := &noticeSink{err: errors.New("delivery unavailable")}
	opts := f.options()
	opts.Deliver = sink.deliver
	o := f.start(opts)
	f.host.set(func(h *fakeHost) { h.clockErr = errors.New("clock unavailable") })
	if err := o.do(o.tick); err == nil {
		t.Fatal("failed clock reading succeeded")
	}
	for range 3 {
		o.notices.cycle()
	}
	f.host.set(func(h *fakeHost) { h.clockErr = nil })
	if err := o.do(o.tick); err != nil {
		t.Fatal(err)
	}
	criticalGap(t, o, p, f.host)
	sink.set(nil)
	o.notices.cycle()
	if sink.count() != 4 || len(sink.last()) != 2 {
		t.Fatalf("stop backoff hid the new ledger notices: %d deliveries", sink.count())
	}
	if q := o.QueueStatuses(now.Add(2 * time.Minute))["notices"]; q.Depth != 1 || q.Reason != "consumer_stalled" {
		t.Fatalf("stop backoff lost queue health after the ledger delivery: %+v", q)
	}
	now = now.Add(10 * time.Second)
	o.notices.cycle()
	if sink.count() != 5 || len(sink.last()) != 1 || !strings.Contains(sink.last()[0].Details, "clock unavailable") {
		t.Fatalf("scheduled stop retry did not deliver: %d deliveries", sink.count())
	}
	if q := o.QueueStatuses(now)["notices"]; q.Depth != 0 || q.Status == "degraded" {
		t.Fatalf("delivered stop alert did not recover queue health: %+v", q)
	}
}

func TestOwnerStopDuringNoticeBackoff(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newOwnerFixture(t)
		f.host.set(func(h *fakeHost) { h.clockErr = errors.New("clock unavailable") })
		sink := &noticeSink{err: errors.New("delivery unavailable")}
		opts := f.options()
		opts.NoticeEvery = 5 * time.Second
		opts.Deliver = sink.deliver
		o := f.start(opts)
		time.Sleep(20 * time.Second)
		synctest.Wait()
		if sink.count() != 3 {
			t.Fatalf("attempts before shutdown = %d, want 3", sink.count())
		}
		before := time.Now()
		o.Stop()
		if !time.Now().Equal(before) {
			t.Fatal("Stop waited for the pending notice retry")
		}
		select {
		case <-o.notices.done:
		default:
			t.Fatal("Stop returned before the sender exited")
		}
		time.Sleep(time.Hour)
		if sink.count() != 3 {
			t.Fatalf("shutdown delivered the pending retry: %d attempts", sink.count())
		}
	})
}
