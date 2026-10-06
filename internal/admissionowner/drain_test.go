package admissionowner

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/store"
)

func (h *fakeHost) now() time.Time {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.wall
}

func (h *fakeHost) clockReads() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.reads
}

// submit hands the owner's ingress one observation of 192.0.2.10 made at
// at, as a detector will once routing goes through the ingress.
func submit(t *testing.T, o *Owner, p *admission.Producer, cursor string, at time.Time) {
	t.Helper()
	submitObservation(t, o, p, "192.0.2.10", cursor, at)
}

// submitTo hands the ingress one observation of addr.
func submitTo(t *testing.T, o *Owner, p *admission.Producer, addr string, at time.Time) {
	t.Helper()
	submitObservation(t, o, p, addr, "offset=1", at)
}

func submitObservation(t *testing.T, o *Owner, p *admission.Producer, addr, cursor string, at time.Time) {
	t.Helper()
	if err := submitObservationError(o, p, addr, cursor, at); err != nil {
		t.Fatal(err)
	}
}

func submitObservationError(o *Owner, p *admission.Producer, addr, cursor string, at time.Time) error {
	target, err := admission.CanonicalAddress(addr, admission.Caps{IPv6: true})
	if err != nil {
		return err
	}
	e, err := p.Mint(admission.EvidenceInput{
		Check: "ssh_brute", FindingID: "0123456789abcdef", Severity: admission.SeverityHigh,
		Observation: admission.ObservationRef{Stream: "log:sshd_log", Cursor: cursor, Version: 1},
		ObservedAt:  at, Parser: admission.ParserRef{Name: "sshd", Version: 1}, Target: target,
	})
	if err != nil {
		return err
	}
	return o.ingress.Submit(admission.Submission{Kind: admission.KindBlockIP, Target: target, Evidence: e})
}

// queuedCandidates reads the durable queue's candidates on the owner
// goroutine.
func queuedCandidates(t *testing.T, o *Owner) []admission.Candidate {
	t.Helper()
	var out []admission.Candidate
	if err := o.do(func() error {
		snap, err := o.ledger.QueueSnapshot()
		if err != nil {
			return err
		}
		for _, it := range snap.Items {
			c, err := o.ledger.Candidate(admission.CandidateID(it.Key))
			if err != nil {
				return err
			}
			out = append(out, c)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return out
}

// The owner drains what detectors hand its ingress into the ledger, which
// gives each target an episode: two observations of one address queue one
// candidate of the episode's first generation (spec 5.2, handoff O16).
func TestOwnerDrainsSubmissionsIntoEpisodes(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	opts := f.options()
	opts.DrainEvery = time.Millisecond
	o := f.start(opts)
	submit(t, o, p, "offset=1", f.host.now())
	submit(t, o, p, "offset=2", f.host.now())
	eventually(t, "the drain", func() bool {
		return o.ingress.Len() == 0 && len(queuedCandidates(t, o)) == 1 && len(queuedCandidates(t, o)[0].Roots) == 2
	})
	c := queuedCandidates(t, o)[0]
	if c.Key.Episode.IsZero() || c.Key.Generation != 1 {
		t.Fatalf("drained candidate key = %+v", c.Key)
	}
}

// Handoff O8: a drain records a fresh clock reading first, so the ledger
// judges arrivals at the current time. A drain with nothing new since the
// last one reads no clock and writes nothing.
func TestOwnerTicksBeforeEachDrain(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	o := f.start(f.options())
	submit(t, o, p, "offset=1", f.host.now())
	f.host.advance(3 * time.Minute)
	if err := o.do(o.drain); err != nil {
		t.Fatal(err)
	}
	var last time.Time
	if err := o.do(func() error { last = o.lastTick; return nil }); err != nil {
		t.Fatal(err)
	}
	if !last.Equal(f.host.now()) || o.ingress.Len() != 0 || len(queuedCandidates(t, o)) != 1 {
		t.Fatalf("drain: last tick %v, want %v; %d held", last, f.host.now(), o.ingress.Len())
	}
	reads, writes := f.host.clockReads(), f.db.WriteTxID()
	if err := o.do(o.drain); err != nil {
		t.Fatal(err)
	}
	if f.host.clockReads() != reads || f.db.WriteTxID() != writes {
		t.Fatal("an idle drain read the clock")
	}
}

// Handoff O30: a clean stop drains what the ingress still holds before it
// closes the generation, so nothing a detector handed over is lost.
func TestOwnerStopDrainsHeldWork(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	o := f.start(f.options())
	submit(t, o, p, "offset=1", f.host.now())
	o.Stop()
	o = f.start(f.options())
	if ls := ledgerStatus(t, o); ls.Ingress.Interrupted != 0 || ls.Ingress.Generation != 2 {
		t.Fatalf("after a clean stop with held work: %+v", ls.Ingress)
	}
	if got := queuedCandidates(t, o); len(got) != 1 {
		t.Fatalf("queued after the stop = %d", len(got))
	}
}

// A stop drains held work in several groups when one cannot hold it all.
func TestOwnerStopDrainsEveryGroup(t *testing.T) {
	p := withTestRegistry(t)
	prev := drainGroup
	drainGroup = 1
	t.Cleanup(func() { drainGroup = prev })
	f := newOwnerFixture(t)
	o := f.start(f.options())
	for _, addr := range []string{"192.0.2.10", "192.0.2.11", "192.0.2.12", "192.0.2.13", "192.0.2.14", "192.0.2.15"} {
		submitTo(t, o, p, addr, f.host.now())
	}
	o.Stop()
	o = f.start(f.options())
	if ls := ledgerStatus(t, o); ls.Ingress.Interrupted != 0 {
		t.Fatalf("after a clean stop with six held groups: %+v", ls.Ingress)
	}
	if got := queuedCandidates(t, o); len(got) != 6 {
		t.Fatalf("queued after the stop = %d", len(got))
	}
}

// A failed drain keeps its work held and names its cause in the owner's
// status, so the stopped-ingress notice can name it too.
func TestOwnerReportsAFailedDrain(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	sink := &noticeSink{}
	opts := f.options()
	opts.Deliver = sink.deliver
	o := f.start(opts)
	submit(t, o, p, "offset=1", f.host.now())
	if err := o.do(o.ledger.EndIngress); err != nil {
		t.Fatal(err)
	}
	if err := o.do(o.drain); err == nil {
		t.Fatal("a drain without an open generation succeeded")
	}
	if st := o.status(); st.Ingress.Admitting || !strings.Contains(st.Owner.Error, "draining the ingress") || o.ingress.Len() != 1 {
		t.Fatalf("after a failed drain: %+v, %d held", st.Owner, o.ingress.Len())
	}
	o.notices.cycle()
	if got := sink.last(); len(got) != 1 || !strings.Contains(got[0].Details, "draining the ingress") {
		t.Fatalf("stopped-ingress notice lost the drain cause: %+v", got)
	}
}

// A timer drain yields after its bound; clean stop then drains the entire
// suffix. More than four groups distinguishes these contracts.
func TestOwnerDrainYieldsWithHeldGroups(t *testing.T) {
	p := withTestRegistry(t)
	prev := drainGroup
	drainGroup = 1
	t.Cleanup(func() { drainGroup = prev })
	f := newOwnerFixture(t)
	o := f.start(f.options())
	for _, addr := range []string{"192.0.2.10", "192.0.2.11", "192.0.2.12", "192.0.2.13", "192.0.2.14", "192.0.2.15"} {
		submitTo(t, o, p, addr, f.host.now())
	}
	if err := o.do(o.drain); err != nil {
		t.Fatal(err)
	}
	if o.ingress.Len() != 2 || len(queuedCandidates(t, o)) != 4 {
		t.Fatalf("bounded drain: %d held, %d queued", o.ingress.Len(), len(queuedCandidates(t, o)))
	}
	if err := o.do(o.drain); err != nil {
		t.Fatal(err)
	}
	if o.ingress.Len() != 0 || len(queuedCandidates(t, o)) != 6 {
		t.Fatal("held work was not drained with an unchanged decision sequence")
	}
}

// Submit and snapshot publication interleave with draining. Every accepted
// address must persist, without a race or a lost held group.
func TestOwnerDrainWithConcurrentSubmit(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	opts := f.options()
	opts.DrainEvery = time.Millisecond
	o := f.start(opts)
	var wg sync.WaitGroup
	errs := make(chan error, 32)
	for i := 1; i <= 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- submitObservationError(o, p, fmt.Sprintf("2001:db8::%x", i), fmt.Sprintf("offset=%d", i), f.host.now())
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	eventually(t, "concurrent submissions to persist", func() bool {
		return o.ingress.Len() == 0 && len(queuedCandidates(t, o)) == 32
	})
	// Producer goroutines are joined before the shutdown checkpoint (O30).
	o.Stop()
	o = f.start(f.options())
	if got := queuedCandidates(t, o); len(got) != 32 || ledgerStatus(t, o).Ingress.Interrupted != 0 {
		t.Fatalf("concurrent drain lost work at stop: %d candidates", len(got))
	}
}

// failingLedger fails group commits or queue snapshots on demand.
type failingLedger struct {
	admission.Ledger
	groups, snapshots *atomic.Bool
}

func (l failingLedger) EnqueueGroup(a []admission.Arrival, c *admission.IngressCheckpoint) ([]admission.ArrivalResult, int, error) {
	if l.groups.Load() {
		return nil, 0, errors.New("group write unavailable")
	}
	return l.Ledger.EnqueueGroup(a, c)
}

func (l failingLedger) QueueSnapshot() (*admission.QueueSnapshot, error) {
	if l.snapshots.Load() {
		return nil, errors.New("snapshot unavailable")
	}
	return l.Ledger.QueueSnapshot()
}

func withFailingDrains(t *testing.T) (groups, snapshots *atomic.Bool) {
	t.Helper()
	groups, snapshots = &atomic.Bool{}, &atomic.Bool{}
	prev := drainGroupOf
	drainGroupOf = func(in *admission.Ingress, l *store.AdmissionLedger, items []admission.IngressItem) (admission.DrainReport, error) {
		return in.DrainTaken(failingLedger{Ledger: l, groups: groups, snapshots: snapshots}, items, arrivalRequest)
	}
	t.Cleanup(func() { drainGroupOf = prev })
	return groups, snapshots
}

// A lasting drain failure keeps admission closed through every tick and is
// announced once, with its cause. The next successful drain reopens
// admission and clears the cause.
func TestOwnerFailedDrainHoldsAdmissionUntilADrainSucceeds(t *testing.T) {
	p := withTestRegistry(t)
	groups, _ := withFailingDrains(t)
	groups.Store(true)
	f := newOwnerFixture(t)
	sink := &noticeSink{}
	opts := f.options()
	opts.Deliver = sink.deliver
	o := f.start(opts)
	submit(t, o, p, "offset=1", f.host.now())
	for range 3 {
		if err := o.do(o.drain); err == nil {
			t.Fatal("a drain succeeded while group writes fail")
		}
		if err := o.do(o.tick); err != nil {
			t.Fatal(err)
		}
		if o.ingress.Health().Admitting {
			t.Fatal("a tick reopened admission after a failed drain")
		}
		o.notices.cycle()
	}
	if got := sink.last(); sink.count() != 1 || len(got) != 1 || !strings.Contains(got[0].Details, "draining the ingress") {
		t.Fatalf("stop notices = %d, last %+v", sink.count(), got)
	}
	groups.Store(false)
	if err := o.do(o.drain); err != nil {
		t.Fatal(err)
	}
	if st := o.status(); !st.Ingress.Admitting || st.Owner.Error != "" || len(queuedCandidates(t, o)) != 1 {
		t.Fatalf("after recovery: %+v", st.Owner)
	}
}

// A drain whose group committed but whose snapshot read failed holds no
// work and no new decision, yet it is retried until admission reopens.
func TestOwnerRetriesADrainWhoseSnapshotFailed(t *testing.T) {
	p := withTestRegistry(t)
	_, snapshots := withFailingDrains(t)
	prev := drainGroup
	drainGroup = 1
	t.Cleanup(func() { drainGroup = prev })
	f := newOwnerFixture(t)
	o := f.start(f.options())
	for _, addr := range []string{"192.0.2.10", "192.0.2.11", "192.0.2.12", "192.0.2.13", "192.0.2.14"} {
		submitTo(t, o, p, addr, f.host.now())
	}
	if err := o.do(o.drain); err != nil || o.ingress.Len() != 1 {
		t.Fatalf("first turn: %v, %d held", err, o.ingress.Len())
	}
	snapshots.Store(true)
	if err := o.do(o.drain); err == nil || o.ingress.Len() != 0 || o.ingress.Health().Admitting {
		t.Fatalf("failed snapshot: %v, %d held, admitting %v", err, o.ingress.Len(), o.ingress.Health().Admitting)
	}
	snapshots.Store(false)
	if err := o.do(o.drain); err != nil || !o.ingress.Health().Admitting || len(queuedCandidates(t, o)) != 5 {
		t.Fatalf("retry: %v, admitting %v", err, o.ingress.Health().Admitting)
	}
}
