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

// noticeSink records every delivery and fails as told.
type noticeSink struct {
	mu         sync.Mutex
	deliveries [][]alert.Finding
	err        error
}

func (s *noticeSink) deliver(fs []alert.Finding) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.deliveries = append(s.deliveries, append([]alert.Finding(nil), fs...))
	return s.err
}

func (s *noticeSink) set(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.err = err
}

func (s *noticeSink) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.deliveries)
}

func (s *noticeSink) last() []alert.Finding {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.deliveries[len(s.deliveries)-1]
}

// criticalGap ends a Critical candidate without its response, which raises
// a withheld notice and counts in the Critical summary.
func criticalGap(t *testing.T, o *Owner, p *admission.Producer, host *fakeHost) {
	t.Helper()
	id, _ := queued(t, o, p, host, admission.SeverityCritical)
	if err := o.do(func() error { _, err := o.ledger.Terminate(id, admission.ReasonPolicy); return err }); err != nil {
		t.Fatal(err)
	}
}

// Disposition C and handoffs O50-O51: due notices go out through the
// independent path as their registered checks, and each delivered count is
// acknowledged with its record's first time. An acknowledgement that fails
// after delivery is retried without delivering again; nothing is due again
// within its interval.
func TestOwnerDeliversNoticesOnTheIndependentPath(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	sink := &noticeSink{}
	opts := f.options()
	opts.Deliver = sink.deliver
	o := f.start(opts)
	criticalGap(t, o, p, f.host)
	failAck := true
	prev := ackNotices
	ackNotices = func(l *store.AdmissionLedger, acks []admission.NoticeAck) error {
		if failAck {
			failAck = false
			return errors.New("ledger busy")
		}
		return prev(l, acks)
	}
	t.Cleanup(func() { ackNotices = prev })
	o.notices.cycle()
	if sink.count() != 1 {
		t.Fatalf("deliveries = %d", sink.count())
	}
	notices := sink.last()
	if len(notices) != 2 {
		t.Fatalf("notices = %+v, want the withheld record and the Critical summary", notices)
	}
	var keyed, summary int
	for _, fd := range notices {
		if fd.Check != "auto_response_withheld" || fd.Severity != alert.Critical || !strings.Contains(fd.Details, "events=1") {
			t.Errorf("notice = %+v", fd)
		}
		if strings.Contains(fd.Details, "reason=policy") && strings.Contains(fd.Details, "check=ssh_brute") && strings.Contains(fd.Details, "examples=cand_") {
			keyed++
		}
		if strings.Contains(fd.Message, "summary") {
			summary++
		}
	}
	if keyed != 1 || summary != 1 {
		t.Fatalf("notices = %+v, want one keyed record and one summary", notices)
	}
	o.notices.cycle()
	o.notices.cycle()
	if sink.count() != 1 {
		t.Fatalf("a retried acknowledgement delivered again: %d deliveries", sink.count())
	}
	var due []admission.NoticeRecord
	if err := o.do(func() (err error) { due, err = o.ledger.PendingNotices(); return err }); err != nil || len(due) != 0 {
		t.Fatalf("still due after acknowledgement: %+v, %v", due, err)
	}
}

// O51: a failed delivery leaves the records pending and reports through
// queue health; the next delivery sends them.
func TestOwnerNoticeDeliveryFailureIsVisible(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	sink := &noticeSink{err: errors.New("mail relay down")}
	opts := f.options()
	opts.Deliver = sink.deliver
	o := f.start(opts)
	criticalGap(t, o, p, f.host)
	o.notices.cycle()
	if s := o.QueueStatuses(time.Now().Add(10 * time.Minute))["notices"]; s.Status != "degraded" || s.Depth == 0 {
		t.Fatalf("failed notice delivery = %+v", s)
	}
	sink.set(nil)
	o.notices.cycle()
	if n := sink.count(); n != 2 || len(sink.last()) != 2 {
		t.Fatalf("deliveries = %d", n)
	}
	if s := o.QueueStatuses(time.Now().Add(10 * time.Minute))["notices"]; s.Status == "degraded" || s.Depth != 0 {
		t.Fatalf("recovered notice delivery = %+v", s)
	}
}

// Ruling 9 and O52: when the ingress stops admitting, one Critical notice
// goes out through the same path, naming the cause; it is sent again only
// after admission resumed and stopped again. A failed send is retried.
func TestOwnerAnnouncesAStoppedIngressOnce(t *testing.T) {
	f := newOwnerFixture(t)
	sink := &noticeSink{}
	opts := f.options()
	opts.Deliver = sink.deliver
	o := f.start(opts)
	o.notices.cycle()
	if sink.count() != 0 {
		t.Fatalf("an admitting ingress was announced: %+v", sink.last())
	}
	f.host.set(func(h *fakeHost) { h.clockErr = errors.New("clock unavailable") })
	_ = o.do(o.tick)
	sink.set(errors.New("mail relay down"))
	o.notices.cycle()
	sink.set(nil)
	o.notices.cycle()
	o.notices.cycle()
	if sink.count() != 2 {
		t.Fatalf("deliveries = %d, want one failed and one sent", sink.count())
	}
	stop := sink.last()
	if len(stop) != 1 || stop[0].Check != "auto_response_withheld" || stop[0].Severity != alert.Critical || !strings.Contains(stop[0].Details, "clock unavailable") {
		t.Fatalf("stop notice = %+v", stop)
	}
	f.host.set(func(h *fakeHost) { h.clockErr = nil })
	_ = o.do(o.tick)
	o.notices.cycle()
	f.host.set(func(h *fakeHost) { h.clockErr = errors.New("clock unavailable") })
	_ = o.do(o.tick)
	o.notices.cycle()
	if sink.count() != 3 {
		t.Fatalf("a second stop was not announced: %d deliveries", sink.count())
	}
}

// A start that cannot open the ledger is a stopped ingress too.
func TestOwnerAnnouncesAFailedStart(t *testing.T) {
	f := newOwnerFixture(t)
	f.host.set(func(h *fakeHost) { h.clockErr = errors.New("clock unavailable") })
	sink := &noticeSink{}
	opts := f.options()
	opts.Deliver = sink.deliver
	o := f.start(opts)
	o.notices.cycle()
	if sink.count() != 1 || !strings.Contains(sink.last()[0].Details, "clock unavailable") {
		t.Fatalf("a failed start was not announced: %d", sink.count())
	}
}

// Stop returns only after a notice delivery in flight has finished, so the
// daemon can close the history store behind it.
func TestOwnerStopWaitsForANoticeDelivery(t *testing.T) {
	f := newOwnerFixture(t)
	f.host.set(func(h *fakeHost) { h.clockErr = errors.New("clock unavailable") })
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	opts := f.options()
	opts.NoticeEvery = time.Millisecond
	opts.Deliver = func([]alert.Finding) error {
		once.Do(func() { close(entered) })
		<-release
		return nil
	}
	o := f.start(opts)
	<-entered
	stopped := make(chan struct{})
	go func() { o.Stop(); close(stopped) }()
	select {
	case <-stopped:
		t.Fatal("Stop returned during a delivery")
	case <-time.After(50 * time.Millisecond):
	}
	close(release)
	<-stopped
}

// An acknowledgement stall cannot hide the independent stopped notice.
func TestOwnerStopNoticeSurvivesAnAckFailure(t *testing.T) {
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
	if sink.count() != 1 {
		t.Fatal("initial delivery missing")
	}
	f.host.set(func(h *fakeHost) { h.clockErr = errors.New("clock unavailable") })
	_ = o.do(o.tick)
	o.notices.cycle()
	if sink.count() != 2 || len(sink.last()) != 1 || !strings.Contains(sink.last()[0].Message, "admission stopped") {
		t.Fatal("ack failure hid the stop")
	}
	o.notices.cycle()
	if sink.count() != 2 {
		t.Fatal("unacknowledged notices repeated")
	}
}

// Recovery can happen entirely between sender polls.
func TestOwnerAnnouncesStopsAcrossABriefRecovery(t *testing.T) {
	f := newOwnerFixture(t)
	sink := &noticeSink{}
	opts := f.options()
	opts.Deliver = sink.deliver
	o := f.start(opts)
	f.host.set(func(h *fakeHost) { h.clockErr = errors.New("clock unavailable") })
	_ = o.do(o.tick)
	o.notices.cycle()
	f.host.set(func(h *fakeHost) { h.clockErr = nil })
	_ = o.do(o.tick)
	f.host.set(func(h *fakeHost) { h.clockErr = errors.New("clock unavailable") })
	_ = o.do(o.tick)
	o.notices.cycle()
	if sink.count() != 2 {
		t.Fatal("a distinct stop was lost between polls")
	}
}

// A failed independent send stays visible even with no ledger notices.
func TestOwnerFailedStopNoticeReportsQueueHealth(t *testing.T) {
	f := newOwnerFixture(t)
	sink := &noticeSink{err: errors.New("delivery unavailable")}
	opts := f.options()
	opts.Deliver = sink.deliver
	f.host.set(func(h *fakeHost) { h.clockErr = errors.New("clock unavailable") })
	o := f.start(opts)
	o.notices.cycle()
	o.notices.cycle()
	if q := o.QueueStatuses(time.Now().Add(10 * time.Minute))["notices"]; q.Status != "degraded" || q.Depth == 0 {
		t.Fatalf("failed stop: %+v", q)
	}
	sink.set(nil)
	o.notices.cycle()
	if q := o.QueueStatuses(time.Now().Add(10 * time.Minute))["notices"]; q.Depth != 0 || q.Status == "degraded" {
		t.Fatalf("recovered stop: %+v", q)
	}
}

// A sender cycle after Stop is inert, including when the shutdown tick failed.
func TestOwnerShutdownDoesNotAnnounceAnOutage(t *testing.T) {
	f := newOwnerFixture(t)
	sink := &noticeSink{}
	opts := f.options()
	opts.Deliver = sink.deliver
	o := f.start(opts)
	f.host.set(func(h *fakeHost) { h.clockErr = errors.New("clock unavailable") })
	o.Stop()
	o.notices.cycle()
	if sink.count() != 0 {
		t.Fatal("shutdown sent a stopped-ingress notice")
	}
}

// Recovery before the owner's cause read must not produce a stopped notice.
func TestOwnerReadsStopAndCauseTogether(t *testing.T) {
	reg, _, err := Registry()
	if err != nil {
		t.Fatal(err)
	}
	in, err := admission.NewIngress(reg)
	if err != nil {
		t.Fatal(err)
	}
	sink := &noticeSink{}
	o := &Owner{opts: Options{Deliver: sink.deliver}, ingress: in, requests: make(chan request), done: make(chan struct{}), tickErr: errors.New("clock unavailable")}
	s := &sender{o: o}
	result := make(chan bool, 1)
	go func() { result <- s.announceStop() }()
	r := <-o.requests
	in.Publish(&admission.QueueSnapshot{})
	o.tickErr = nil
	r.err <- r.fn()
	if pending := <-result; pending || sink.count() != 0 {
		t.Fatalf("recovered ingress produced a stop notice: pending=%v deliveries=%d", pending, sink.count())
	}
}
