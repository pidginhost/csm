package admissionowner

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/alert"
)

// noticeOwner starts an owner with an engine under the policies r
// publishes, delivering notices to sink.
func noticeOwner(t *testing.T, f *ownerFixture, first ExecutionPolicy, sink *noticeSink) (*Owner, *policyReader) {
	t.Helper()
	r := &policyReader{p: first}
	opts := executeOptions(f, newFakeBlocks())
	opts.Policy, opts.Deliver = r.read, sink.deliver
	return f.start(opts), r
}

// Notices follow the installed policy (design C10): while the owner
// executes, a gap is an outage of automatic blocking, so ledger notices go
// to the alert channels with their kind's severity and no preview prefix,
// including while a refused policy holds that execution. A dry run keeps
// them previews in history only, as Warnings.
func TestOwnerNoticesFollowTheInstalledPolicy(t *testing.T) {
	for _, tc := range []struct {
		name    string
		policy  ExecutionPolicy
		refuse  bool
		preview bool
	}{
		{"dry_run", dryPolicy(1), false, true},
		{"live", validPolicy(1), false, false},
		{"refused_live", validPolicy(1), true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := withTestRegistry(t)
			f := newOwnerFixture(t)
			sink := &noticeSink{}
			o, r := noticeOwner(t, f, tc.policy, sink)
			if tc.refuse {
				invalid := validPolicy(2)
				invalid.AskVerdict = nil
				r.publish(invalid)
				if err := o.Reload(); !errors.Is(err, ErrPolicy) {
					t.Fatalf("invalid policy = %v", err)
				}
			}
			criticalGap(t, o, p, f.host)
			o.notices.cycle()
			if sink.count() != 1 || sink.lastPreview() != tc.preview {
				t.Fatalf("deliveries %d, preview %v; want one with preview %v", sink.count(), sink.lastPreview(), tc.preview)
			}
			for _, fd := range sink.last() {
				wantSeverity, prefixed := alert.Critical, strings.HasPrefix(fd.Message, "Admission preview: ")
				if tc.preview {
					wantSeverity = alert.Warning
				}
				if fd.Check != "auto_response_withheld" || fd.Severity != wantSeverity || prefixed != tc.preview {
					t.Errorf("notice = %+v", fd)
				}
			}
		})
	}
}

// A notice keeps the mode it was raised in. One raised while the owner
// executed reports a gap of a live period and stays live after a dry run
// starts; one raised in a dry run stays a preview after execution returns.
func TestOwnerNoticesKeepTheModeTheyWereRaisedIn(t *testing.T) {
	for _, toLive := range []bool{false, true} {
		t.Run(map[bool]string{false: "live_then_dry_run", true: "dry_run_then_live"}[toLive], func(t *testing.T) {
			p := withTestRegistry(t)
			f := newOwnerFixture(t)
			sink := &noticeSink{}
			o, r := noticeOwner(t, f, validPolicy(1), sink)
			later := func() {
				t.Helper()
				f.host.advance(time.Second)
				if err := o.do(o.tick); err != nil {
					t.Fatal(err)
				}
			}
			install := func(next ExecutionPolicy) {
				t.Helper()
				later()
				r.publish(next)
				if err := o.do(o.refreshPolicy); err != nil {
					t.Fatal(err)
				}
				later()
			}
			if toLive {
				install(dryPolicy(2))
			}
			criticalGap(t, o, p, f.host)
			if toLive {
				install(validPolicy(3))
			} else {
				install(dryPolicy(2))
			}
			if err := o.do(func() error {
				if !o.ledger.LiveStarted() {
					t.Error("the fixture ledger never started live")
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			o.notices.cycle()
			if sink.count() != 1 || sink.lastPreview() != toLive {
				t.Fatalf("deliveries %d, preview %v; want one with preview %v", sink.count(), sink.lastPreview(), toLive)
			}
			wantSeverity := alert.Critical
			if toLive {
				wantSeverity = alert.Warning
			}
			for _, fd := range sink.last() {
				if fd.Severity != wantSeverity || strings.HasPrefix(fd.Message, "Admission preview: ") != toLive {
					t.Errorf("notice = %+v", fd)
				}
			}
		})
	}
}

// A policy can change while startup has no admission clock yet. That
// failed live start must not turn later dry-run events into live notices.
func TestOwnerNoticeModeAfterClockFailureAtStartup(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	sink := &noticeSink{}
	previous, _ := noticeOwner(t, f, validPolicy(1), sink)
	previous.Stop()
	f.host.set(func(h *fakeHost) { h.clockErr = errors.New("clock unavailable") })
	o, r := noticeOwner(t, f, validPolicy(1), sink)
	if ownerStarted(t, o) {
		t.Fatal("fixture startup did not fail")
	}
	r.publish(dryPolicy(2))
	f.host.set(func(h *fakeHost) { h.clockErr = nil })
	if err := o.do(func() error {
		o.startErr = o.start()
		return o.startErr
	}); err != nil {
		t.Fatal(err)
	}
	f.host.advance(time.Second)
	if err := o.do(o.tick); err != nil {
		t.Fatal(err)
	}
	criticalGap(t, o, p, f.host)
	o.notices.cycle()
	if sink.count() != 1 || !sink.lastPreview() || len(sink.last()) != 2 {
		t.Fatalf("dry-run gap after startup recovery: %d deliveries, preview %v, findings %+v", sink.count(), sink.lastPreview(), sink.last())
	}
}

// Restored notices retain the initial startup mode even when a clock
// failure delays startup until after another policy is installed.
func TestOwnerRestoredNoticeKeepsStartupModeAfterClockFailure(t *testing.T) {
	for _, live := range []bool{false, true} {
		t.Run(fmt.Sprintf("startup_live_%v", live), func(t *testing.T) {
			p := withTestRegistry(t)
			f := newOwnerFixture(t)
			previous, _ := noticeOwner(t, f, validPolicy(1), &noticeSink{})
			criticalGap(t, previous, p, f.host)
			previous.Stop()
			f.host.set(func(h *fakeHost) { h.clockErr = errors.New("clock unavailable") })
			first, next := dryPolicy(1), validPolicy(2)
			if live {
				first, next = validPolicy(1), dryPolicy(2)
			}
			sink := &noticeSink{}
			o, r := noticeOwner(t, f, first, sink)
			if ownerStarted(t, o) {
				t.Fatal("fixture startup did not fail")
			}
			r.publish(next)
			f.host.set(func(h *fakeHost) { h.clockErr = nil })
			f.host.advance(time.Second)
			if err := o.do(func() error {
				o.startErr = o.start()
				return o.startErr
			}); err != nil {
				t.Fatal(err)
			}
			o.notices.cycle()
			if sink.count() != 1 || sink.lastPreview() == live || len(sink.last()) != 2 {
				t.Fatalf("restored gap: %d deliveries, preview %v, findings %+v", sink.count(), sink.lastPreview(), sink.last())
			}
		})
	}
}

// A record is live when it comes only from a real attempt, or when an
// event it has not delivered may fall in a live span of this process.
// Undelivered events are no older than the read of the last acknowledged
// delivery, when this process made it, else than the acknowledgement.
func TestRaisedLiveNotices(t *testing.T) {
	at := func(s int) time.Time { return time.Unix(1000+int64(s), 0) }
	spans := []liveSpan{{since: at(10), until: at(20)}, {since: at(30)}}
	reason := admission.NoticeKey{Kind: admission.NoticeWithheld, Reason: admission.ReasonPolicy, Check: "ssh_brute", Effect: admission.EffectAddress}
	outcome := admission.NoticeKey{Kind: admission.NoticeWithheld, Outcome: admission.DispositionFailed, Check: "ssh_brute", Effect: admission.EffectAddress}
	var never time.Time
	for _, tc := range []struct {
		name        string
		key         admission.NoticeKey
		first, last time.Time
		sent, read  time.Time
		want        bool
	}{
		{"before_any_span", reason, at(1), at(9), never, never, false},
		{"inside_a_closed_span", reason, at(12), at(15), never, never, true},
		{"between_spans", reason, at(21), at(29), never, never, false},
		{"straddles_a_flip", reason, at(5), at(11), never, never, true},
		{"at_a_span_end", reason, at(20), at(20), never, never, true},
		{"in_the_open_span", reason, at(31), at(40), never, never, true},
		{"live_events_delivered", reason, at(12), at(25), at(21), never, false},
		{"raised_during_a_delivery", reason, at(12), at(25), at(21), at(15), true},
		{"read_after_the_span", reason, at(12), at(25), at(23), at(21), false},
		{"attempt_outcome", outcome, at(1), at(2), never, never, true},
		{"applied_summary", admission.NoticeKey{Kind: admission.NoticeAppliedSummary}, at(1), at(2), never, never, true},
	} {
		r := admission.NoticeRecord{Key: tc.key, Count: 2, Acked: 1, First: tc.first, Last: tc.last, Sent: tc.sent}
		if got := raisedLive(r, spans, tc.read); got != tc.want {
			t.Errorf("%s: live %v, want %v", tc.name, got, tc.want)
		}
	}
	if raisedLive(admission.NoticeRecord{Key: reason, Count: 1, First: at(12), Last: at(12)}, nil, never) {
		t.Error("a record of a process that never executed was live")
	}
	if !raisedLive(admission.NoticeRecord{Key: outcome, Count: 1, First: at(12), Last: at(12)}, nil, never) {
		t.Error("an attempt outcome of an earlier process was a preview")
	}
}

// An event raised while a delivery is out keeps the mode it was raised
// in, though the acknowledgement comes after a switch to a dry run.
func TestOwnerNoticeKeepsLiveEventsRaisedDuringDelivery(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	sink := &noticeSink{}
	o, r := noticeOwner(t, f, validPolicy(1), sink)
	later := func(d time.Duration) {
		t.Helper()
		f.host.advance(d)
		if err := o.do(o.tick); err != nil {
			t.Fatal(err)
		}
	}
	criticalGap(t, o, p, f.host)
	later(time.Second)
	sink.during = func() {
		id, _ := queuedAt(t, o, p, f.host, admission.SeverityCritical, "192.0.2.11")
		if err := o.do(func() error { _, err := o.ledger.Terminate(id, admission.ReasonPolicy); return err }); err != nil {
			t.Fatal(err)
		}
		later(time.Second)
		r.publish(dryPolicy(2))
		if err := o.do(o.refreshPolicy); err != nil {
			t.Fatal(err)
		}
		later(time.Second)
	}
	o.notices.cycle()
	if sink.count() != 1 || sink.lastPreview() {
		t.Fatalf("first delivery: %d, preview %v", sink.count(), sink.lastPreview())
	}
	later(time.Hour)
	o.notices.cycle()
	if sink.count() != 2 || sink.lastPreview() {
		t.Fatalf("events raised during the delivery: %d deliveries, preview %v; want them live", sink.count(), sink.lastPreview())
	}
	for _, fd := range sink.last() {
		if fd.Severity != alert.Critical || strings.HasPrefix(fd.Message, "Admission preview: ") || !strings.HasPrefix(fd.Details, "events=1 ") {
			t.Errorf("notice = %+v", fd)
		}
	}
}

// Pending records can be read before startup gets a valid clock reading.
// Delivery must still retain the saved read time when startup recovers
// and raises new live events before that delivery is acknowledged.
func TestOwnerNoticeReadBeforeStartupClockKeepsLiveEvents(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	previous, _ := noticeOwner(t, f, validPolicy(1), &noticeSink{})
	criticalGap(t, previous, p, f.host)
	previous.Stop()
	f.host.set(func(h *fakeHost) { h.clockErr = errors.New("clock unavailable") })
	r := &policyReader{p: dryPolicy(1)}
	sink := &noticeSink{}
	var during func()
	opts := executeOptions(f, newFakeBlocks())
	opts.Policy = r.read
	opts.Deliver = func(fs []alert.Finding, preview bool) error {
		err := sink.deliver(fs, preview)
		if preview && during != nil {
			fn := during
			during = nil
			fn()
		}
		return err
	}
	o := f.start(opts)
	if ownerStarted(t, o) {
		t.Fatal("fixture startup did not fail")
	}
	advance := func(d time.Duration) {
		t.Helper()
		f.host.advance(d)
		if err := o.do(o.tick); err != nil {
			t.Fatal(err)
		}
	}
	during = func() {
		f.host.set(func(h *fakeHost) { h.clockErr = nil })
		f.host.advance(time.Second)
		r.publish(validPolicy(2))
		if err := o.do(func() error {
			o.startErr = o.start()
			return o.startErr
		}); err != nil {
			t.Fatal(err)
		}
		id, _ := queuedAt(t, o, p, f.host, admission.SeverityCritical, "192.0.2.11")
		if err := o.do(func() error { _, err := o.ledger.Terminate(id, admission.ReasonPolicy); return err }); err != nil {
			t.Fatal(err)
		}
		advance(time.Second)
		r.publish(dryPolicy(3))
		if err := o.Reload(); err != nil {
			t.Fatal(err)
		}
		advance(time.Second)
	}
	o.notices.cycle()
	if ledgerDeliveries(sink) != 1 || !sink.lastPreview() {
		t.Fatalf("startup delivery = %d, preview %v", ledgerDeliveries(sink), sink.lastPreview())
	}
	advance(time.Hour)
	o.notices.cycle()
	if ledgerDeliveries(sink) != 2 || sink.lastPreview() || len(sink.last()) != 2 {
		t.Fatalf("events raised during delivery = %d, preview %v, findings %+v", ledgerDeliveries(sink), sink.lastPreview(), sink.last())
	}
	for _, fd := range sink.last() {
		if fd.Severity != alert.Critical || !strings.HasPrefix(fd.Details, "events=1 ") {
			t.Errorf("live notice = %+v", fd)
		}
	}
}

// Records of both modes go out live first, then as previews, and only
// what went out is acknowledged: a failed preview group stays due and is
// the only one sent again.
func TestOwnerSplitNoticeDeliveryAcknowledgesOnlySuccess(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	sink := &noticeSink{previewErr: errors.New("history unavailable")}
	o, r := noticeOwner(t, f, validPolicy(1), sink)
	later := func() {
		t.Helper()
		f.host.advance(time.Second)
		if err := o.do(o.tick); err != nil {
			t.Fatal(err)
		}
	}
	criticalGap(t, o, p, f.host)
	later()
	r.publish(dryPolicy(2))
	if err := o.do(o.refreshPolicy); err != nil {
		t.Fatal(err)
	}
	later()
	// Another reason keys another record, raised only in the dry run.
	id, _ := queuedAt(t, o, p, f.host, admission.SeverityCritical, "192.0.2.12")
	if err := o.do(func() error { _, err := o.ledger.Terminate(id, admission.ReasonInvalid); return err }); err != nil {
		t.Fatal(err)
	}
	o.notices.cycle()
	if sink.count() != 2 {
		t.Fatalf("deliveries = %d, want the live group and the preview group", sink.count())
	}
	live, livePreview := sink.delivery(0)
	previews, previewed := sink.delivery(1)
	if livePreview || !previewed || len(live) == 0 || len(previews) == 0 {
		t.Fatalf("groups: %d live (preview %v), %d previews (preview %v)", len(live), livePreview, len(previews), previewed)
	}
	sink.setPreview(nil)
	o.notices.cycle()
	if sink.count() != 3 {
		t.Fatalf("the retry sent %d deliveries in all; want only the previews again", sink.count())
	}
	if again, preview := sink.delivery(2); !preview || !reflect.DeepEqual(messages(again), messages(previews)) {
		t.Fatalf("the retry sent %+v (preview %v); want only the previews", again, preview)
	}
	o.notices.cycle()
	if sink.count() != 3 {
		t.Fatalf("an acknowledged group went out again: %d deliveries", sink.count())
	}
}

// A successful live group cannot erase repeated failures of the preview
// group in the same ledger batch.
func TestOwnerSplitNoticeDeliveryKeepsBackoff(t *testing.T) {
	clock := &testClock{t: time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)}
	previous := deliveryNow
	deliveryNow = clock.now
	t.Cleanup(func() { deliveryNow = previous })
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	sink := &noticeSink{previewErr: errors.New("history unavailable")}
	o, r := noticeOwner(t, f, validPolicy(1), sink)
	advance := func() {
		t.Helper()
		f.host.advance(time.Minute)
		clock.advance(time.Minute)
		if err := o.do(o.tick); err != nil {
			t.Fatal(err)
		}
	}
	gap := func(addr string, reason admission.Reason) {
		t.Helper()
		id, _ := queuedAt(t, o, p, f.host, admission.SeverityCritical, addr)
		if err := o.do(func() error { _, err := o.ledger.Terminate(id, reason); return err }); err != nil {
			t.Fatal(err)
		}
	}
	criticalGap(t, o, p, f.host)
	advance()
	r.publish(dryPolicy(2))
	if err := o.Reload(); err != nil {
		t.Fatal(err)
	}
	advance()
	gap("192.0.2.11", admission.ReasonInvalid)
	o.notices.cycle()
	advance()
	r.publish(validPolicy(3))
	if err := o.Reload(); err != nil {
		t.Fatal(err)
	}
	for i := range 2 {
		advance()
		gap(fmt.Sprintf("192.0.2.%d", 12+i), admission.ReasonPolicy)
		o.notices.cycle()
	}
	if sink.count() != 6 {
		t.Fatalf("deliveries = %d, want three live/preview pairs", sink.count())
	}
	for i := range 6 {
		fs, preview := sink.delivery(i)
		if len(fs) == 0 || preview != (i%2 == 1) {
			t.Fatalf("delivery %d: %d findings, preview %v", i, len(fs), preview)
		}
	}
	sink.setPreview(nil)
	o.notices.cycle()
	if sink.count() != 6 {
		t.Fatalf("partial successes erased preview backoff: %d deliveries", sink.count())
	}
	clock.advance(2 * defaultNoticeEvery)
	o.notices.cycle()
	if sink.count() != 7 || !sink.lastPreview() || len(sink.last()) != 1 {
		t.Fatalf("retry = %d deliveries, last %+v, preview %v", sink.count(), sink.last(), sink.lastPreview())
	}
	o.notices.cycle()
	if sink.count() != 7 {
		t.Fatal("an acknowledged group was delivered again")
	}
}

// A delivery of every due group ends the backoff: a later failure is
// retried at once again, as after any first failure.
func TestOwnerNoticeDeliveryResetsBackoffAfterSuccess(t *testing.T) {
	clock := &testClock{t: time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)}
	previous := deliveryNow
	deliveryNow = clock.now
	t.Cleanup(func() { deliveryNow = previous })
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	sink := &noticeSink{}
	failing := func(err error) {
		sink.mu.Lock()
		sink.err = err
		sink.mu.Unlock()
	}
	failing(errors.New("history unavailable"))
	o, _ := noticeOwner(t, f, validPolicy(1), sink)
	criticalGap(t, o, p, f.host)
	for range 3 {
		o.notices.cycle()
	}
	if sink.count() != 3 {
		t.Fatalf("failing deliveries = %d, want 3", sink.count())
	}
	failing(nil)
	clock.advance(4 * defaultNoticeEvery)
	o.notices.cycle()
	if sink.count() != 4 {
		t.Fatalf("delivery after the wait = %d deliveries, want 4", sink.count())
	}
	f.host.advance(time.Minute)
	if err := o.do(o.tick); err != nil {
		t.Fatal(err)
	}
	id, _ := queuedAt(t, o, p, f.host, admission.SeverityCritical, "192.0.2.11")
	if err := o.do(func() error { _, err := o.ledger.Terminate(id, admission.ReasonPolicy); return err }); err != nil {
		t.Fatal(err)
	}
	failing(errors.New("history unavailable"))
	o.notices.cycle()
	o.notices.cycle()
	if sink.count() != 6 {
		t.Fatalf("a failure after a full delivery waited: %d deliveries, want two more at once", sink.count())
	}
}

// messages is the messages of fs, in order.
func messages(fs []alert.Finding) []string {
	out := make([]string, len(fs))
	for i, fd := range fs {
		out[i] = fd.Message
	}
	return out
}

// A kind whose severity is a Warning stays one while the owner executes.
func TestOwnerLiveNoticeKeepsAWarningKind(t *testing.T) {
	if got := alertSeverity(admission.NoticeWithheldWarning); got != alert.Warning {
		t.Fatalf("withheld warning = %v", got)
	}
	if got := alertSeverity(admission.NoticeAppliedSummary); got != alert.Warning {
		t.Fatalf("applied summary = %v", got)
	}
	if got := alertSeverity(admission.NoticeCapacity); got != alert.Critical {
		t.Fatalf("capacity = %v", got)
	}
}

// While the owner executes, a stopped ingress stops automatic blocking:
// its notice is Critical and says so (design C10).
func TestOwnerAnnouncesAStoppedLiveIngressAsCritical(t *testing.T) {
	f := newOwnerFixture(t)
	sink := &noticeSink{}
	o, _ := noticeOwner(t, f, validPolicy(1), sink)
	f.host.set(func(h *fakeHost) { h.clockErr = errors.New("clock unavailable") })
	_ = o.do(o.tick)
	o.notices.cycle()
	stop := sink.last()
	if len(stop) != 1 || stop[0].Check != "auto_response_withheld" || stop[0].Severity != alert.Critical || sink.lastPreview() ||
		stop[0].Message != "Automatic response admission stopped; automatic blocks are not applied" {
		t.Fatalf("stop notice = %+v (preview %v)", stop, sink.lastPreview())
	}
}

// A failed stop delivery is reworded in the mode of its eventual retry,
// without changing the original stop identity, cause or timestamp.
func TestOwnerStopNoticeRetryUsesCurrentMode(t *testing.T) {
	for _, toLive := range []bool{false, true} {
		t.Run(map[bool]string{false: "to_dry_run", true: "to_live"}[toLive], func(t *testing.T) {
			f := newOwnerFixture(t)
			sink := &noticeSink{err: errors.New("delivery unavailable")}
			first, next := validPolicy(1), dryPolicy(2)
			if toLive {
				first, next = dryPolicy(1), validPolicy(2)
			}
			o, r := noticeOwner(t, f, first, sink)
			f.host.set(func(h *fakeHost) { h.clockErr = errors.New("clock unavailable") })
			if err := o.do(o.tick); err == nil {
				t.Fatal("fixture did not stop admission")
			}
			o.notices.cycle()
			before := sink.last()[0]
			r.publish(next)
			// Install the mode without repairing the stopped ingress.
			if err := o.do(o.refreshPolicy); err != nil {
				t.Fatal(err)
			}
			sink.set(nil)
			o.notices.cycle()
			after := sink.last()[0]
			severity := alert.Warning
			message := "Automatic response admission preview stopped; existing blocking is unaffected"
			if toLive {
				severity = alert.Critical
				message = "Automatic response admission stopped; automatic blocks are not applied"
			}
			if sink.lastPreview() || after.Severity != severity || after.Message != message || after.Details != before.Details || !after.Timestamp.Equal(before.Timestamp) {
				t.Fatalf("retried stop = %+v, original %+v", after, before)
			}
		})
	}
}

// Production still sends ledger previews to history and the independent
// stop Warning to alerts. Compare the complete frozen finding, not a prefix.
func TestOwnerNoticeProductionBytesStayUnchanged(t *testing.T) {
	withLiveExecution(t, false)
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	sink := &noticeSink{}
	o, _ := noticeOwner(t, f, validPolicy(1), sink)
	id, at := queued(t, o, p, f.host, admission.SeverityCritical)
	if err := o.do(func() error { _, err := o.ledger.Terminate(id, admission.ReasonPolicy); return err }); err != nil {
		t.Fatal(err)
	}
	o.notices.cycle()
	got := sink.last()
	if len(got) != 2 || !sink.lastPreview() {
		t.Fatalf("production ledger deliveries = %+v", got)
	}
	stamp := at.UTC().Format(time.RFC3339)
	prefix := fmt.Sprintf("events=1 first=%s last=%s", stamp, stamp)
	wants := map[string]string{
		"Admission preview: Critical automatic response withheld":     prefix + " reason=policy check=ssh_brute effect=address examples=" + string(id),
		"Admission preview: Critical automatic response gaps summary": prefix + " examples=" + string(id),
	}
	for _, fd := range got {
		details, ok := wants[fd.Message]
		if !ok {
			t.Fatalf("unexpected or repeated production notice: %+v", fd)
		}
		want := alert.Finding{Check: "auto_response_withheld", Severity: alert.Warning, Message: fd.Message, Details: details, Timestamp: fd.Timestamp}
		if !reflect.DeepEqual(fd, want) {
			t.Fatalf("production notice = %+v, want %+v", fd, want)
		}
		delete(wants, fd.Message)
	}
	f.host.set(func(h *fakeHost) { h.clockErr = errors.New("clock unavailable") })
	if err := o.do(o.tick); err == nil {
		t.Fatal("fixture did not stop admission")
	}
	o.notices.cycle()
	got = sink.last()
	h := o.Status().Ingress
	if len(got) != 1 || sink.lastPreview() {
		t.Fatalf("production stop deliveries = %+v", got)
	}
	want := alert.Finding{Check: "auto_response_withheld", Severity: alert.Warning,
		Message:   "Automatic response admission preview stopped; existing blocking is unaffected",
		Details:   fmt.Sprintf("since=%s critical_refused=%d cause=clock unavailable", h.StoppedSince.UTC().Format(time.RFC3339), h.CriticalRefused),
		Timestamp: got[0].Timestamp}
	if !reflect.DeepEqual(got[0], want) {
		t.Fatalf("production stop = %+v, want %+v", got[0], want)
	}
}
