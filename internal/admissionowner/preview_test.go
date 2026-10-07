package admissionowner

import (
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/store"
)

// fakeMono is a monotonic clock the test moves.
type fakeMono struct {
	mu  sync.Mutex
	now time.Time
}

func (m *fakeMono) read() time.Time {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.now
}

func (m *fakeMono) advance(d time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.now = m.now.Add(d)
}

func previewOptions(f *ownerFixture) Options {
	opts := f.options()
	opts.Expiry = func(admission.Candidate) time.Duration { return 24 * time.Hour }
	return opts
}

func outcomes(s admission.LedgerStatus, d admission.Disposition) uint64 {
	var n uint64
	for _, row := range s.Outcomes.Hour {
		if row.Outcome == d.String() {
			n += row.N
		}
	}
	return n
}

// The owner serves what it drained as observe previews: each pick is
// reserved and charged as live work would be, with the expiry the
// configured response would use, and ends without running. Nothing stays
// queued and nothing is applied (rulings R1, R2).
func TestOwnerPreviewsDrainedWork(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	opts := previewOptions(f)
	opts.DrainEvery, opts.ScheduleEvery = time.Millisecond, time.Millisecond
	o := f.start(opts)
	submitTo(t, o, p, "192.0.2.10", f.host.now())
	submitTo(t, o, p, "192.0.2.11", f.host.now())
	eventually(t, "the previews", func() bool {
		return outcomes(ledgerStatus(t, o), admission.DispositionObserve) == 2
	})
	s := ledgerStatus(t, o)
	if len(queuedCandidates(t, o)) != 0 || s.Ceiling.General.Used != 2 || outcomes(s, admission.DispositionApplied) != 0 {
		t.Fatalf("queued %d, general charges %d, applied %d", len(queuedCandidates(t, o)), s.Ceiling.General.Used, outcomes(s, admission.DispositionApplied))
	}
	rows := pendingAudit(t, o)
	if len(rows) != 4 {
		t.Fatalf("audit rows = %d, want a reservation and a preview each", len(rows))
	}
	for _, r := range rows {
		if !r.ExpiresAt.Equal(f.host.now().Add(24*time.Hour)) || (r.State != admission.StateReserved && r.State != admission.StateObserved) {
			t.Fatalf("audit row %s expiring %v", r.State, r.ExpiresAt)
		}
	}
}

// Work the ceiling cannot serve now waits, deferred, until the ledger's wake
// time, converted with the admission clock's elapsed time (handoffs
// O15-O17): the owner previews it at that time and not before.
func TestOwnerPreviewsDeferredWorkAtTheLedgerWakeTime(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	// Six an hour: a general lane of four units that saves one.
	f.host.set(func(h *fakeHost) { h.limit = 6 })
	mono := &fakeMono{now: time.Now()}
	prev := monoNow
	monoNow = mono.read
	t.Cleanup(func() { monoNow = prev })
	o := f.start(previewOptions(f))
	submitTo(t, o, p, "192.0.2.10", f.host.now())
	submitTo(t, o, p, "192.0.2.11", f.host.now())
	if err := o.do(o.drain); err != nil {
		t.Fatal(err)
	}
	if err := o.do(func() error { o.schedule(); return nil }); err != nil {
		t.Fatal(err)
	}
	waiting := queuedCandidates(t, o)
	if outcomes(ledgerStatus(t, o), admission.DispositionObserve) != 1 || len(waiting) != 1 || waiting[0].Reason != admission.ReasonCeiling {
		t.Fatalf("after the first turn: %d previews, waiting %+v", outcomes(ledgerStatus(t, o), admission.DispositionObserve), waiting)
	}
	var wake time.Time
	if err := o.do(func() error { wake = o.wakeAt; return nil }); err != nil {
		t.Fatal(err)
	}
	if got := wake.Sub(mono.read()); got != 15*time.Minute {
		t.Fatalf("wake in %v, want the quarter hour one unit takes to refill", got)
	}
	f.host.advance(15*time.Minute - time.Second)
	mono.advance(15*time.Minute - time.Second)
	if err := o.do(func() error { o.schedule(); return nil }); err != nil {
		t.Fatal(err)
	}
	if n := outcomes(ledgerStatus(t, o), admission.DispositionObserve); n != 1 {
		t.Fatalf("previewed before the wake time: %d", n)
	}
	f.host.advance(time.Second)
	mono.advance(time.Second)
	if err := o.do(func() error { o.schedule(); return nil }); err != nil {
		t.Fatal(err)
	}
	if n := outcomes(ledgerStatus(t, o), admission.DispositionObserve); n != 2 || len(queuedCandidates(t, o)) != 0 {
		t.Fatalf("at the wake time: %d previews, %d queued", n, len(queuedCandidates(t, o)))
	}
}

// A schedule the ledger refuses is the owner's error until a later turn
// succeeds; the turn is retried.
func TestOwnerReportsAFailedSchedule(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	failing := errors.New("injected schedule failure")
	prev := scheduleLedger
	scheduleLedger = func(*store.AdmissionLedger, admission.ScheduleLimits) ([]admission.Pick, error) { return nil, failing }
	t.Cleanup(func() { scheduleLedger = prev })
	o := f.start(previewOptions(f))
	submitTo(t, o, p, "192.0.2.10", f.host.now())
	if err := o.do(o.drain); err != nil {
		t.Fatal(err)
	}
	if err := o.do(func() error { o.schedule(); return nil }); err != nil {
		t.Fatal(err)
	}
	if s := o.status().Owner; !strings.Contains(s.Error, failing.Error()) {
		t.Fatalf("owner error = %q", s.Error)
	}
	scheduleLedger = prev
	if err := o.do(func() error { o.schedule(); return nil }); err != nil {
		t.Fatal(err)
	}
	if s := o.status().Owner; s.Error != "" || outcomes(ledgerStatus(t, o), admission.DispositionObserve) != 1 {
		t.Fatalf("after recovery: error %q, %d previews", s.Error, outcomes(ledgerStatus(t, o), admission.DispositionObserve))
	}
}

// More ready work than one batch takes the next turn at once: the ledger's
// wake time is now, so the owner does not wait for a new arrival.
func TestOwnerServesTheRestOfTheQueueOnTheNextTurn(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	prev := previewLimits
	previewLimits.Members = 1
	t.Cleanup(func() { previewLimits = prev })
	o := f.start(previewOptions(f))
	submitTo(t, o, p, "192.0.2.10", f.host.now())
	submitTo(t, o, p, "192.0.2.11", f.host.now())
	if err := o.do(o.drain); err != nil {
		t.Fatal(err)
	}
	for turn := 1; turn <= 2; turn++ {
		if err := o.do(func() error { o.schedule(); return nil }); err != nil {
			t.Fatal(err)
		}
		if n := outcomes(ledgerStatus(t, o), admission.DispositionObserve); n != uint64(turn) {
			t.Fatalf("after turn %d: %d previews", turn, n)
		}
	}
}

// A drain that queued work calls the next turn: the queue was empty at the
// previous one and the ledger had no wake time to give.
func TestOwnerTakesATurnAfterADrain(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	o := f.start(previewOptions(f))
	turn := func() {
		t.Helper()
		if err := o.do(func() error { o.schedule(); return nil }); err != nil {
			t.Fatal(err)
		}
	}
	turn()
	submitTo(t, o, p, "192.0.2.10", f.host.now())
	if err := o.do(o.drain); err != nil {
		t.Fatal(err)
	}
	turn()
	if n := outcomes(ledgerStatus(t, o), admission.DispositionObserve); n != 1 {
		t.Fatalf("previews after the drain = %d", n)
	}
}
