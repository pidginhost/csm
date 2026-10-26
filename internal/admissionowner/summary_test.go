package admissionowner

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/alert"
)

// A summary sink must be cancellable both during ordinary delivery and
// during the final flush. No cancelled summary disappears from health.
func TestSummaryStopCancelsDelivery(t *testing.T) {
	for _, inFlight := range []bool{false, true} {
		t.Run(fmt.Sprintf("in_flight=%v", inFlight), func(t *testing.T) {
			p := withTestRegistry(t)
			f := newOwnerFixture(t)
			blocks := newFakeBlocks()
			opts := executeOptions(f, blocks)
			opts.Policy = func() ExecutionPolicy { return dryPolicy(1) }
			entered := make(chan struct{}, 1)
			opts.DeliverSummary = func(ctx context.Context, _ alert.Finding) error {
				entered <- struct{}{}
				<-ctx.Done()
				return ctx.Err()
			}
			if inFlight {
				opts.NoticeEvery = time.Millisecond
			}
			o := f.start(opts)
			mono := heldMono(t, o)
			queueMany(t, o, p, f, 1, 1)
			turn(t, o)
			mono.advance(summaryEvery)
			if inFlight {
				select {
				case <-entered:
				case <-time.After(2 * time.Second):
					t.Fatal("summary delivery did not start")
				}
				if err := o.do(func() error { return nil }); err != nil {
					t.Fatal(err)
				}
			}
			stopped := make(chan struct{})
			go func() { o.Stop(); close(stopped) }()
			select {
			case <-stopped:
			case <-time.After(2 * time.Second):
				t.Fatal("Stop blocked on summary delivery")
			}
			d := o.Status().Owner.DryRun
			if d.SummariesLost != 1 || !d.ComparisonIncomplete {
				t.Fatalf("cancelled summary not counted: %+v", d)
			}
		})
	}
}

// A sink may commit just as shutdown cancels its context. Its success
// receipt must still settle once, without retrying or reporting a loss.
func TestSummaryStopSettlesACommittedDelivery(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	opts := executeOptions(f, newFakeBlocks())
	opts.Policy = func() ExecutionPolicy { return dryPolicy(1) }
	opts.NoticeEvery = time.Millisecond
	entered := make(chan alert.Finding, 1)
	calls := 0
	opts.DeliverSummary = func(ctx context.Context, finding alert.Finding) error {
		calls++
		entered <- finding
		<-ctx.Done()
		return nil
	}
	o := f.start(opts)
	mono := heldMono(t, o)
	queueMany(t, o, p, f, 2, 1)
	turn(t, o)
	mono.advance(summaryEvery)
	select {
	case finding := <-entered:
		if finding.Message != "Dry-run capacity forecast: 2 responses passed modelled capacity checks" {
			t.Fatalf("summary = %+v", finding)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("summary delivery did not start")
	}
	o.Stop()
	if calls != 1 || o.Status().Owner.DryRun.SummariesLost != 0 {
		t.Fatalf("committed delivery: %d calls, %d lost", calls, o.Status().Owner.DryRun.SummariesLost)
	}
}

// summaryOwner is a dry-run owner whose notices sink records deliveries.
func summaryOwner(t *testing.T, f *ownerFixture, blocks *fakeBlocks) (*Owner, *policyReader, *fakeMono, *noticeSink) {
	t.Helper()
	sink := &noticeSink{}
	r := &policyReader{p: dryPolicy(1)}
	opts := executeOptions(f, blocks)
	opts.Policy, opts.Deliver = r.read, sink.deliver
	opts.DeliverSummary = func(_ context.Context, f alert.Finding) error {
		return sink.deliver([]alert.Finding{f}, true)
	}
	o := f.start(opts)
	return o, r, heldMono(t, o), sink
}

// summaries are the dry-run summaries the sink received.
func (s *noticeSink) summaries() []alert.Finding {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []alert.Finding
	for i, fs := range s.deliveries {
		for _, f := range fs {
			if strings.HasPrefix(f.Message, "Dry-run capacity forecast:") {
				if !s.previews[i] {
					f.Message = "NOT A PREVIEW: " + f.Message
				}
				out = append(out, f)
			}
		}
	}
	return out
}

// detail is the value of key in a summary's details.
func detail(f alert.Finding, key string) string {
	for _, field := range strings.Fields(f.Details) {
		if v, ok := strings.CutPrefix(field, key+"="); ok {
			return v
		}
	}
	return ""
}

// queueMany queues n block picks at distinct addresses.
func queueMany(t *testing.T, o *Owner, p *admission.Producer, f *ownerFixture, n, from int) []admission.CandidateID {
	t.Helper()
	var ids []admission.CandidateID
	for i := range n {
		id, _ := queuedAt(t, o, p, f.host, admission.SeverityHigh, fmt.Sprintf("2001:db8::%x", from+i))
		ids = append(ids, id)
	}
	return ids
}

// Spec 3.8, 6.4: 200 committed predictions in one interval give one
// history-only auto_block Warning a minute after the first: the capacity
// admissions in its message, every other prediction counted, and exactly
// 20 distinct examples, the first in committed order, each naming its
// candidate, finding, target and check. An empty interval gives none.
func TestOwnerSummarizesADryRunMinute(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	blocks := newFakeBlocks()
	// Of 188 slots the reserve holds 38 the general picks never take.
	blocks.limit = 188
	o, _, mono, sink := summaryOwner(t, f, blocks)
	w := watchExamples(t, o)
	queueMany(t, o, p, f, 200, 1)
	for range 4 {
		turn(t, o)
	}
	if n := len(queuedCandidates(t, o)); n != 0 {
		t.Fatalf("fixture: %d picks left", n)
	}
	mono.advance(summaryEvery - time.Nanosecond)
	o.notices.cycle()
	if got := sink.summaries(); len(got) != 0 {
		t.Fatalf("a summary before its minute: %+v", got)
	}
	mono.advance(time.Nanosecond)
	o.notices.cycle()
	got := sink.summaries()
	if len(got) != 1 {
		t.Fatalf("summaries = %+v, want one", got)
	}
	s := got[0]
	if s.Check != "auto_block" || s.Severity != alert.Warning || s.Message != "Dry-run capacity forecast: 150 responses passed modelled capacity checks" {
		t.Fatalf("summary = %+v", s)
	}
	if detail(s, "set_full") != "50" || detail(s, "ceiling") != "0" || detail(s, "not_modelled") != "0" || detail(s, "sessions") != "1" ||
		detail(s, "start") == "" || detail(s, "end") == "" {
		t.Fatalf("summary details = %q", s.Details)
	}
	examples := strings.Split(detail(s, "examples"), ",")
	if len(examples) != summaryExamples {
		t.Fatalf("%d examples, want %d: %q", len(examples), summaryExamples, s.Details)
	}
	var first []string
	for _, batch := range w.written() {
		for _, b := range batch {
			if len(first) < summaryExamples {
				first = append(first, string(b.Candidate)+"/"+b.IP+"/"+b.Check)
			}
		}
	}
	for i, e := range examples {
		parts := strings.Split(e, "/")
		if len(parts) != 4 || parts[0]+"/"+parts[2]+"/"+parts[3] != first[i] || parts[1] != "0123456789abcdef" {
			t.Fatalf("example %d = %q, want %q with its finding", i, e, first[i])
		}
	}
	mono.advance(summaryEvery)
	o.notices.cycle()
	if n := len(sink.summaries()); n != 1 {
		t.Fatalf("an empty interval delivered: %d summaries", n)
	}
}

// Predictions that arrive while a summary is delivered start the next
// one: the delivered copy never changes and nothing is lost when it is
// acknowledged. The next summary waits a minute after the previous
// attempt.
func TestOwnerSummaryDeliversAnImmutableCopy(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	blocks := newFakeBlocks()
	o, _, mono, sink := summaryOwner(t, f, blocks)
	queueMany(t, o, p, f, 2, 1)
	turn(t, o)
	mono.advance(summaryEvery)
	var during func()
	inner := o.opts.DeliverSummary
	setOwnerHook(t, o, &o.opts.DeliverSummary, func(ctx context.Context, finding alert.Finding) error {
		if during != nil {
			during()
		}
		return inner(ctx, finding)
	})
	during = func() {
		// The owner forecasts while the sender delivers.
		queueMany(t, o, p, f, 3, 10)
		turn(t, o)
	}
	o.notices.cycle()
	during = nil
	got := sink.summaries()
	if len(got) != 1 || !strings.HasPrefix(got[0].Message, "Dry-run capacity forecast: 2 ") || len(strings.Split(detail(got[0], "examples"), ",")) != 2 {
		t.Fatalf("first summary = %+v", got)
	}
	mono.advance(summaryEvery - time.Nanosecond)
	o.notices.cycle()
	if n := len(sink.summaries()); n != 1 {
		t.Fatalf("the next summary came within a minute of the last attempt: %d", n)
	}
	mono.advance(time.Nanosecond)
	o.notices.cycle()
	if got = sink.summaries(); len(got) != 2 || !strings.HasPrefix(got[1].Message, "Dry-run capacity forecast: 3 ") {
		t.Fatalf("second summary = %+v", got)
	}
}

// A failed delivery keeps the summary and coalesces later intervals into
// it, with the earlier examples first and a session count; the next
// attempt waits a minute after the failed one. A failure never reaches the
// detection alert stream: every summary is history only.
func TestOwnerSummaryRetriesAndCoalesces(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	blocks := newFakeBlocks()
	o, r, mono, sink := summaryOwner(t, f, blocks)
	first := queueMany(t, o, p, f, 2, 1)
	turn(t, o)
	sink.set(errors.New("history unavailable"))
	mono.advance(summaryEvery)
	o.notices.cycle()
	if sink.count() != 1 || len(sink.summaries()) != 1 {
		t.Fatalf("fixture: %d deliveries", sink.count())
	}
	// A new dry-run session joins the pending summary.
	r.publish(validPolicy(2))
	turn(t, o)
	r.publish(dryPolicy(3))
	queueMany(t, o, p, f, 2, 10)
	turn(t, o)
	sink.set(nil)
	mono.advance(summaryEvery - time.Nanosecond)
	o.notices.cycle()
	if n := len(sink.summaries()); n != 1 {
		t.Fatalf("retried within a minute of the failed attempt: %d", n)
	}
	mono.advance(time.Nanosecond)
	o.notices.cycle()
	got := sink.summaries()
	if len(got) != 2 {
		t.Fatalf("summaries = %d", len(got))
	}
	s := got[1]
	examples := strings.Split(detail(s, "examples"), ",")
	if !strings.HasPrefix(s.Message, "Dry-run capacity forecast: 4 ") || detail(s, "sessions") != "2" || len(examples) != 4 ||
		!strings.HasPrefix(examples[0], string(first[0])+"/") && !strings.HasPrefix(examples[0], string(first[1])+"/") {
		t.Fatalf("coalesced summary = %+v", s)
	}
	for _, fs := range got {
		if strings.HasPrefix(fs.Message, "NOT A PREVIEW") {
			t.Fatalf("a summary reached the alert channels: %+v", fs)
		}
	}
	if d := dryRunState(t, o); d.SummariesLost != 0 {
		t.Fatalf("a retried summary counted as lost: %+v", d)
	}
}

// Spec 3.8: a mode change never flushes a summary early or relabels it;
// it is delivered as a dry-run summary at its time, and live work adds
// nothing to it.
func TestOwnerSummaryOutlivesAFlipToLive(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	blocks := newFakeBlocks()
	o, r, mono, sink := summaryOwner(t, f, blocks)
	queueMany(t, o, p, f, 1, 1)
	turn(t, o)
	r.publish(validPolicy(2))
	if err := o.Reload(); err != nil {
		t.Fatal(err)
	}
	queueMany(t, o, p, f, 1, 10)
	turn(t, o)
	o.notices.cycle()
	if n := len(sink.summaries()); n != 0 {
		t.Fatalf("a flip flushed the summary early: %d", n)
	}
	mono.advance(summaryEvery)
	o.notices.cycle()
	if got := sink.summaries(); len(got) != 1 || !strings.HasPrefix(got[0].Message, "Dry-run capacity forecast: 1 ") {
		t.Fatalf("summary after the flip = %+v", got)
	}
}

// Spec 3.8: Stop sends a summary its minute allows and otherwise counts it
// discarded; it never sends one early.
func TestOwnerStopDiscardsAnEarlySummary(t *testing.T) {
	for _, due := range []bool{false, true} {
		t.Run(fmt.Sprintf("due=%v", due), func(t *testing.T) {
			p := withTestRegistry(t)
			f := newOwnerFixture(t)
			blocks := newFakeBlocks()
			o, _, mono, sink := summaryOwner(t, f, blocks)
			queueMany(t, o, p, f, 1, 1)
			turn(t, o)
			if due {
				mono.advance(summaryEvery)
			}
			o.Stop()
			got := sink.summaries()
			lost := o.Status().Owner.DryRun.SummariesLost
			switch {
			case due && (len(got) != 1 || lost != 0):
				t.Fatalf("a due summary at stop: %d sent, %d lost", len(got), lost)
			case !due && (len(got) != 0 || lost != 1):
				t.Fatalf("an early summary at stop: %d sent, %d lost", len(got), lost)
			}
		})
	}
}
