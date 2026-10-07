package admissionowner

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/store"
)

func comparisonClock(t *testing.T, now func() time.Time) {
	t.Helper()
	previous := deliveryNow
	deliveryNow = now
	t.Cleanup(func() { deliveryNow = previous })
}

func TestDecisionCountsIncludeTerminatedPreviews(t *testing.T) {
	withTestRegistry(t)
	f := newOwnerFixture(t)
	comparisonClock(t, f.host.now)
	sink := &actionSink{}
	opts := respondOptions(f)
	opts.WriteAudit, opts.ScheduleEvery = sink.write, time.Hour
	o := f.start(opts)
	for i, addr := range []string{"192.0.2.10", "192.0.2.11"} {
		finding := sshFinding(f.host.now(), addr, alert.High)
		finding.SourceIP = addr
		root, err := o.Mint(finding, addr)
		if err != nil {
			t.Fatal(err)
		}
		ttl := time.Hour
		if i == 0 {
			ttl = time.Duration(1<<63 - 1)
		}
		if err := o.Respond(admission.KindBlockIP, root, admission.EntryIncident, ttl); err != nil {
			t.Fatal(err)
		}
	}
	if err := o.do(o.drain); err != nil {
		t.Fatal(err)
	}
	f.host.advance(time.Hour)
	for range 2 {
		if err := o.do(o.preview); err != nil {
			t.Fatal(err)
		}
	}
	o.Stop()
	want := []string{
		"2026-10-04T13:00:00Z block_ip unknown incident queued  2",
		"2026-10-04T14:00:00Z block_ip unknown incident observe  1",
		"2026-10-04T14:00:00Z block_ip unknown incident refused invalid 1",
	}
	if got := sink.previews(); !equalStrings(got, want) {
		t.Fatalf("terminal preview decisions = %q, want %q", got, want)
	}
}

func TestDecisionCountsFlushAfterAFailedFinalDrain(t *testing.T) {
	for _, failure := range []string{"clock", "group", "final checkpoint"} {
		t.Run(failure, func(t *testing.T) {
			p := withTestRegistry(t)
			f := newOwnerFixture(t)
			comparisonClock(t, f.host.now)
			sink := &actionSink{}
			opts := f.options()
			opts.WriteAudit = sink.write
			o := f.start(opts)
			o.Refuse(admission.KindBlockIP, sshFinding(f.host.now(), "offset=1", alert.High), 0, admission.ErrEvidenceConflict)
			submit(t, o, p, "offset=2", f.host.now())
			previous := drainGroupOf
			switch failure {
			case "clock":
				f.host.set(func(h *fakeHost) { h.clockErr = errors.New("clock unavailable") })
			case "group":
				setOwnerHook(t, o, &drainGroupOf, func(*admission.Ingress, *store.AdmissionLedger, []admission.IngressItem) (admission.DrainReport, error) {
					return admission.DrainReport{}, errors.New("group unavailable")
				})
			case "final checkpoint":
				setOwnerHook(t, o, &drainGroupOf, func(in *admission.Ingress, l *store.AdmissionLedger, items []admission.IngressItem) (admission.DrainReport, error) {
					if len(items) == 0 {
						return admission.DrainReport{}, errors.New("checkpoint unavailable")
					}
					return previous(in, l, items)
				})
			}
			o.Stop()
			want := []string{"2026-10-04T13:00:00Z block_ip unknown scan refused invalid 1"}
			if failure == "final checkpoint" {
				want = append([]string{"2026-10-04T13:00:00Z block_ip unknown scan queued  1"}, want...)
			}
			if got := sink.previews(); !equalStrings(got, want) {
				t.Fatalf("%s lost completed decisions: %q, want %q", failure, got, want)
			}
		})
	}
}

func TestDecisionCountsUseTheClockOfAPartialStart(t *testing.T) {
	f := newOwnerFixture(t)
	f.host.set(func(h *fakeHost) { h.limit = 0 })
	wall := f.host.now().Add(-2 * time.Hour)
	comparisonClock(t, func() time.Time { return wall })
	sink := &actionSink{}
	opts := f.options()
	opts.WriteAudit = sink.write
	o := f.start(opts)
	if o.Status().Owner.Error == "" {
		t.Fatal("invalid ceiling did not stop startup")
	}
	o.Refuse(admission.KindBlockIP, sshFinding(wall, "offset=1", alert.High), 0, errors.New("startup unavailable"))
	o.Stop()
	want := []string{"2026-10-04T13:00:00Z block_ip unknown scan refused invalid 1"}
	if got := sink.previews(); !equalStrings(got, want) {
		t.Fatalf("partial startup regressed below the admission hour: %q", got)
	}
}

func TestDecisionCountsFlushWhileTheClockIsUnavailable(t *testing.T) {
	f := newOwnerFixture(t)
	comparisonClock(t, f.host.now)
	sink := &actionSink{}
	opts := f.options()
	opts.WriteAudit = sink.write
	o := f.start(opts)
	o.Refuse(admission.KindBlockIP, sshFinding(f.host.now(), "offset=1", alert.High), 0, errors.New("invalid observation"))
	f.host.advance(time.Hour)
	f.host.set(func(h *fakeHost) { h.clockErr = errors.New("clock unavailable") })
	if err := o.do(o.tick); err == nil {
		t.Fatal("unavailable clock succeeded")
	}
	want := []string{"2026-10-04T13:00:00Z block_ip unknown scan refused invalid 1"}
	if got := sink.previews(); !equalStrings(got, want) {
		t.Fatalf("clock outage prevented hourly accounting: %q", got)
	}
}

func TestDecisionCountsFlushWhileTheLedgerCannotStart(t *testing.T) {
	f := newOwnerFixture(t)
	comparisonClock(t, f.host.now)
	sink := &actionSink{}
	opts := f.options()
	opts.DB, opts.WriteAudit, opts.TickEvery = nil, sink.write, time.Millisecond
	o := f.start(opts)
	o.Refuse(admission.KindBlockIP, sshFinding(f.host.now(), "offset=1", alert.High), 0, errors.New("ledger unavailable"))
	f.host.advance(time.Hour)
	eventually(t, "hourly accounting during startup failure", func() bool { return len(sink.previews()) == 1 })
	want := []string{"2026-10-04T13:00:00Z block_ip unknown scan refused invalid 1"}
	if got := sink.previews(); !equalStrings(got, want) {
		t.Fatalf("startup outage summaries = %q", got)
	}
}

func TestDecisionCountsIncludeDisplacedMemoryMerges(t *testing.T) {
	for _, step := range []time.Duration{0, time.Hour} {
		t.Run(step.String(), func(t *testing.T) {
			withTestRegistry(t)
			f := newOwnerFixture(t)
			comparisonClock(t, f.host.now)
			sink := &actionSink{}
			opts := respondOptions(f)
			opts.WriteAudit, opts.ScheduleEvery = sink.write, time.Hour
			opts.Caps = func() admission.Caps { return admission.Caps{IPv6: true} }
			o := f.start(opts)
			var last admission.Evidence
			for i := range admission.IngressPositions {
				addr := fmt.Sprintf("2001:db8::%x", i+1)
				finding := sshFinding(f.host.now(), addr, alert.High)
				finding.SourceIP = addr
				var err error
				last, err = o.Mint(finding, addr)
				if err != nil {
					t.Fatal(err)
				}
				if err := o.Respond(admission.KindBlockIP, last, 0); err != nil {
					t.Fatal(err)
				}
			}
			for range 2 {
				if err := o.Respond(admission.KindBlockIP, last, 0); err != nil {
					t.Fatal(err)
				}
			}
			finding := sshFinding(f.host.now(), "offset=critical", alert.Critical)
			root, err := o.Mint(finding, finding.SourceIP)
			if err != nil {
				t.Fatal(err)
			}
			// A wall step before the owner's next tick must date the loss by the
			// funnel's hour, rather than its older queue snapshot.
			f.host.advance(step)
			if err := o.Respond(admission.KindBlockIP, root, 0); err != nil {
				t.Fatal(err)
			}
			if n := o.ingress.Stats().Counters.Count(admission.CountKey{Event: admission.EventEnded, Reason: admission.ReasonQueueOverflow, Class: admission.ClassC2, Severity: admission.SeverityHigh}); n != 1 {
				t.Fatalf("fixture displaced %d held items", n)
			}
			o.Stop()
			stamp := "2026-10-04T13:00:00Z"
			if step > 0 {
				stamp = "2026-10-04T14:00:00Z"
			}
			want := []string{
				fmt.Sprintf("%s block_ip unknown scan queued  %d", stamp, admission.IngressPositions),
				stamp + " block_ip unknown scan refused queue_overflow 3",
			}
			if got := sink.previews(); !equalStrings(got, want) {
				t.Fatalf("displaced submissions vanished: %q, want %q", got, want)
			}
		})
	}
}
