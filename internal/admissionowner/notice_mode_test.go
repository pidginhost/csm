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
