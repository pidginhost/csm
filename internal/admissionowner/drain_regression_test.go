package admissionowner

import (
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/store"
)

// An observation submitted after the clock was read belongs to a later
// group. Otherwise the ledger refuses valid same-clock evidence as future.
func TestOwnerFreezesEachGroupBeforeReadingItsClock(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	opts := f.options()
	var inject atomic.Bool
	var o *Owner
	opts.Clock = func() (admission.ClockReading, error) {
		reading, err := f.host.clock()
		if inject.Swap(false) {
			f.host.advance(time.Millisecond)
			err = submitObservationError(o, p, "192.0.2.11", "offset=2", f.host.now())
		}
		return reading, err
	}
	o = f.start(opts)
	submit(t, o, p, "offset=1", f.host.now())
	inject.Store(true)
	if err := o.do(o.drain); err != nil {
		t.Fatal(err)
	}
	if got := queuedCandidates(t, o); len(got) != 2 || o.ingress.Len() != 0 {
		t.Fatalf("same-clock arrivals: %d queued, %d held; want both queued", len(got), o.ingress.Len())
	}
}

// Failure before the group commit is still a drain failure. Clock and
// inventory recovery cannot reopen admission until the drain itself works.
func TestOwnerHoldsAdmissionAfterTheDrainTickFails(t *testing.T) {
	for _, failure := range []string{"clock", "snapshot", "ceiling"} {
		t.Run(failure, func(t *testing.T) {
			p := withTestRegistry(t)
			f := newOwnerFixture(t)
			sink := &noticeSink{}
			opts := f.options()
			opts.Deliver = sink.deliver
			o := f.start(opts)
			submit(t, o, p, "offset=1", f.host.now())
			prev := readSnapshot
			t.Cleanup(func() { readSnapshot = prev })
			switch failure {
			case "clock":
				f.host.set(func(h *fakeHost) { h.clockErr = errors.New("clock unavailable") })
			case "snapshot":
				readSnapshot = func(*store.AdmissionLedger) (*admission.QueueSnapshot, error) {
					return nil, errors.New("snapshot unavailable")
				}
			case "ceiling":
				f.host.set(func(h *fakeHost) { h.limit = 0 })
			}
			if err := o.do(o.drain); err == nil {
				t.Fatal("drain accepted a failed tick")
			}
			o.notices.cycle()
			f.host.set(func(h *fakeHost) { h.clockErr, h.limit = nil, 2000 })
			readSnapshot = prev
			if err := o.do(o.tick); err != nil {
				t.Fatal(err)
			}
			if err := o.do(func() error { o.refreshInventory(); return nil }); err != nil {
				t.Fatal(err)
			}
			if st := o.status(); st.Ingress.Admitting || !strings.Contains(st.Owner.Error, "draining the ingress") || o.ingress.Len() != 1 {
				t.Fatalf("tick recovery released the drain hold: %+v %+v", st.Owner, st.Ingress)
			}
			o.notices.cycle()
			if sink.count() != 1 {
				t.Fatalf("stop notices = %d, want one", sink.count())
			}
			if err := o.do(o.drain); err != nil {
				t.Fatal(err)
			}
			if st := o.status(); !st.Ingress.Admitting || st.Owner.Error != "" || len(queuedCandidates(t, o)) != 1 {
				t.Fatalf("successful drain did not recover: %+v %+v", st.Owner, st.Ingress)
			}
		})
	}
}

// A later reload error must not overwrite the cause retained by the drain
// hold once that reload has recovered.
func TestOwnerRetainsDrainCauseAcrossAFailedReload(t *testing.T) {
	p := withTestRegistry(t)
	groups, _ := withFailingDrains(t)
	f := newOwnerFixture(t)
	sink := &noticeSink{}
	opts := f.options()
	opts.Deliver = sink.deliver
	o := f.start(opts)
	submit(t, o, p, "offset=1", f.host.now())
	groups.Store(true)
	if err := o.do(o.drain); err == nil {
		t.Fatal("group write failure succeeded")
	}
	f.host.set(func(h *fakeHost) { h.limit = 0 })
	if err := o.Reload(); err == nil {
		t.Fatal("invalid ceiling succeeded")
	}
	f.host.set(func(h *fakeHost) { h.limit = 2000 })
	if err := o.do(o.tick); err != nil {
		t.Fatal(err)
	}
	if st := o.status(); st.Ingress.Admitting || !strings.Contains(st.Owner.Error, "group write unavailable") {
		t.Fatalf("recovered reload hid the drain cause: %+v", st.Owner)
	}
	o.notices.cycle()
	if got := sink.last(); len(got) != 1 || !strings.Contains(got[0].Details, "group write unavailable") {
		t.Fatalf("recovered reload hid the drain cause from its notice: %+v", got)
	}
	groups.Store(false)
	if err := o.do(o.drain); err != nil {
		t.Fatal(err)
	}
	if st := o.status(); !st.Ingress.Admitting || st.Owner.Error != "" {
		t.Fatalf("drain recovery retained an error: %+v", st.Owner)
	}
}

// Isolation can commit a checkpoint before a transient arrival error. Its
// readable completion snapshot must not reopen a still-failing drain.
type failingIsolationLedger struct {
	admission.Ledger
	calls int
}

func (l *failingIsolationLedger) EnqueueGroup(a []admission.Arrival, cp *admission.IngressCheckpoint) ([]admission.ArrivalResult, int, error) {
	l.calls++
	if l.calls == 1 {
		return nil, 0, admission.ErrCorruptRecord
	}
	if len(a) != 0 {
		return nil, 0, errors.New("isolated arrival unavailable")
	}
	return l.Ledger.EnqueueGroup(a, cp)
}

func TestOwnerFailedIsolationKeepsTheSameAdmissionStop(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	sink := &noticeSink{}
	opts := f.options()
	opts.Deliver = sink.deliver
	o := f.start(opts)
	submit(t, o, p, "offset=1", f.host.now())
	prev := drainGroupOf
	t.Cleanup(func() { drainGroupOf = prev })
	drainGroupOf = func(in *admission.Ingress, l *store.AdmissionLedger, items []admission.IngressItem) (admission.DrainReport, error) {
		return in.DrainTaken(&failingIsolationLedger{Ledger: l}, items, arrivalRequest)
	}
	for range 3 {
		if err := o.do(o.drain); err == nil {
			t.Fatal("failed arrival isolation succeeded")
		}
		o.notices.cycle()
	}
	if sink.count() != 1 || o.ingress.Len() != 1 || len(queuedCandidates(t, o)) != 0 {
		t.Fatalf("lasting isolation failure: %d notices, %d held, %d queued", sink.count(), o.ingress.Len(), len(queuedCandidates(t, o)))
	}
	drainGroupOf = prev
	if err := o.do(o.drain); err != nil {
		t.Fatal(err)
	}
	if st := o.status(); !st.Ingress.Admitting || st.Owner.Error != "" || len(queuedCandidates(t, o)) != 1 {
		t.Fatalf("isolation recovery did not release admission: %+v", st.Owner)
	}
}

// A submission refused after a group checkpoint leaves no held work. Its
// new decision must still trigger the next timer's empty checkpoint.
func TestOwnerCheckpointsARefusalAfterTheLastGroup(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	o := f.start(f.options())
	submit(t, o, p, "offset=1", f.host.now())
	prev := drainGroupOf
	t.Cleanup(func() { drainGroupOf = prev })
	drainGroupOf = func(in *admission.Ingress, l *store.AdmissionLedger, items []admission.IngressItem) (admission.DrainReport, error) {
		report, err := prev(in, l, items)
		if err == nil && len(items) != 0 {
			if submitErr := in.Submit(admission.Submission{}); submitErr == nil {
				return report, errors.New("invalid evidence was accepted")
			}
		}
		return report, err
	}
	if err := o.do(o.drain); err != nil {
		t.Fatal(err)
	}
	if o.ingress.Len() != 0 {
		t.Fatal("the refused submission left held work")
	}
	if err := o.do(o.drain); err != nil {
		t.Fatal(err)
	}
	var cp *admission.IngressCheckpoint
	if err := o.do(func() error {
		snap, err := o.ledger.QueueSnapshot()
		if err == nil {
			cp = snap.Checkpoint
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if cp == nil || cp.Sequence != 2 {
		t.Fatalf("refusal was not checkpointed: %+v", cp)
	}
	reads, writes := f.host.clockReads(), f.db.WriteTxID()
	if err := o.do(o.drain); err != nil {
		t.Fatal(err)
	}
	if f.host.clockReads() != reads || f.db.WriteTxID() != writes {
		t.Fatal("the checkpointed refusal kept an idle drain active")
	}
}

func TestOwnerStopRetriesAFailedDrain(t *testing.T) {
	for _, recover := range []bool{false, true} {
		t.Run(map[bool]string{false: "still failing", true: "recovered"}[recover], func(t *testing.T) {
			p := withTestRegistry(t)
			groups, _ := withFailingDrains(t)
			f := newOwnerFixture(t)
			o := f.start(f.options())
			submit(t, o, p, "offset=1", f.host.now())
			groups.Store(true)
			if err := o.do(o.drain); err == nil {
				t.Fatal("group write failure succeeded")
			}
			groups.Store(!recover)
			o.Stop()
			st := o.Status()
			if st.Ingress.Admitting || st.Ledger.Ingress.Open == recover {
				t.Fatalf("shutdown after a failed drain: %+v %+v", st.Ingress, st.Ledger.Ingress)
			}
			if recover && (st.Owner.Error != "" || o.ingress.Len() != 0) {
				t.Fatalf("successful shutdown kept a drain failure: %+v", st.Owner)
			}
			if !recover && (!strings.Contains(st.Owner.Error, "group write unavailable") || o.ingress.Len() != 1) {
				t.Fatalf("failed shutdown lost its cause or work: %+v", st.Owner)
			}
			groups.Store(false)
			o = f.start(f.options())
			wantInterrupted, wantQueued := uint64(1), 0
			if recover {
				wantInterrupted, wantQueued = 0, 1
			}
			if got := ledgerStatus(t, o).Ingress.Interrupted; got != wantInterrupted || len(queuedCandidates(t, o)) != wantQueued {
				t.Fatalf("restart: %d interruptions, %d queued", got, len(queuedCandidates(t, o)))
			}
		})
	}
}

func TestOwnerStopReportsAFailedFinalCheckpoint(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	o := f.start(f.options())
	submit(t, o, p, "offset=1", f.host.now())
	prev := drainGroupOf
	t.Cleanup(func() { drainGroupOf = prev })
	drainGroupOf = func(in *admission.Ingress, l *store.AdmissionLedger, items []admission.IngressItem) (admission.DrainReport, error) {
		if len(items) == 0 {
			return admission.DrainReport{}, errors.New("final checkpoint unavailable")
		}
		return prev(in, l, items)
	}
	o.Stop()
	if st := o.Status(); !st.Ledger.Ingress.Open || st.Ingress.Admitting || !strings.Contains(st.Owner.Error, "final checkpoint unavailable") {
		t.Fatalf("shutdown hid the final checkpoint failure: %+v %+v", st.Owner, st.Ledger.Ingress)
	}
	drainGroupOf = prev
	o = f.start(f.options())
	if ledgerStatus(t, o).Ingress.Interrupted != 1 || len(queuedCandidates(t, o)) != 1 {
		t.Fatal("failed final checkpoint closed the generation or lost committed work")
	}
}

func TestOwnerStopReportsAFailedGenerationClose(t *testing.T) {
	f := newOwnerFixture(t)
	o := f.start(f.options())
	prev := drainGroupOf
	t.Cleanup(func() { drainGroupOf = prev })
	drainGroupOf = func(in *admission.Ingress, l *store.AdmissionLedger, items []admission.IngressItem) (admission.DrainReport, error) {
		report, err := prev(in, l, items)
		if err == nil {
			err = f.db.Close()
		}
		return report, err
	}
	o.Stop()
	if st := o.Status(); st.Ingress.Admitting || !strings.Contains(st.Owner.Error, "closing the ingress") {
		t.Fatalf("shutdown hid the generation close failure: %+v", st.Owner)
	}
}

// damagedTargetLedger stands in for a ledger whose records for one target
// are damaged after open: every group naming that target fails as corrupt,
// so isolation discards its arrival and every other group commits.
type damagedTargetLedger struct {
	admission.Ledger
	bad admission.Target
}

func (l *damagedTargetLedger) EnqueueGroup(a []admission.Arrival, cp *admission.IngressCheckpoint) ([]admission.ArrivalResult, int, error) {
	for _, x := range a {
		if x.Request.Target == l.bad {
			return nil, 0, admission.ErrCorruptRecord
		}
	}
	return l.Ledger.EnqueueGroup(a, cp)
}

// Damage at one target discards that target's arrivals and counts them
// lost, but it is not a failed drain: admission stays open for every other
// target, no stop is announced however often the target is reported, and
// status keeps the damage cause.
func TestOwnerKeepsAdmissionOpenAroundADamagedTarget(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	sink := &noticeSink{}
	opts := f.options()
	opts.Deliver = sink.deliver
	o := f.start(opts)
	bad, err := admission.CanonicalAddress("192.0.2.66", admission.Caps{IPv6: true})
	if err != nil {
		t.Fatal(err)
	}
	prev := drainGroupOf
	t.Cleanup(func() { drainGroupOf = prev })
	drainGroupOf = func(in *admission.Ingress, l *store.AdmissionLedger, items []admission.IngressItem) (admission.DrainReport, error) {
		return in.DrainTaken(&damagedTargetLedger{Ledger: l, bad: bad}, items, arrivalRequest)
	}
	for i := range 3 {
		f.host.advance(time.Second)
		submitObservation(t, o, p, "192.0.2.66", fmt.Sprintf("offset=%d", i+1), f.host.now())
		submitObservation(t, o, p, fmt.Sprintf("192.0.2.%d", 10+i), "offset=1", f.host.now())
		if err := o.do(o.drain); err != nil {
			t.Fatalf("round %d: isolated damage failed the drain: %v", i, err)
		}
		if !o.ingress.Health().Admitting || o.ingress.Len() != 0 {
			t.Fatalf("round %d: admitting %v, %d held", i, o.ingress.Health().Admitting, o.ingress.Len())
		}
		o.notices.cycle()
	}
	if sink.count() != 0 {
		t.Fatalf("isolated damage announced %d stops: %+v", sink.count(), sink.last())
	}
	if got := queuedCandidates(t, o); len(got) != 3 {
		t.Fatalf("healthy targets queued %d candidates, want 3", len(got))
	}
	st := o.status()
	if st.Owner.Error != "" || !strings.Contains(st.Owner.DamageError, "admission record is corrupt") {
		t.Fatalf("status after isolated damage: %+v", st.Owner)
	}
	// A damaged record stays damaged: a later healthy drain keeps the cause.
	submitObservation(t, o, p, "192.0.2.20", "offset=1", f.host.now())
	if err := o.do(o.drain); err != nil || len(queuedCandidates(t, o)) != 4 || o.status().Owner.DamageError == "" {
		t.Fatalf("a healthy drain cleared the damage cause: %v %+v", err, o.status().Owner)
	}
}
