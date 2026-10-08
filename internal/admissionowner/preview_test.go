package admissionowner

import (
	"errors"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/alert"
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

// Manual fixture timers must leave queued work alone until the test asks
// for a preview, even if the test takes longer than the default period.
func TestOwnerFixtureKeepsPreviewTurnsManual(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p := withTestRegistry(t)
		f := newOwnerFixture(t)
		o := f.start(previewOptions(f))
		submitTo(t, o, p, "192.0.2.10", f.host.now())
		if err := o.do(o.drain); err != nil {
			t.Fatal(err)
		}
		time.Sleep(2 * time.Second)
		synctest.Wait()
		if n := outcomes(ledgerStatus(t, o), admission.DispositionObserve); n != 0 || len(queuedCandidates(t, o)) != 1 {
			t.Fatalf("manual timers ran a preview: %d observed, %d queued", n, len(queuedCandidates(t, o)))
		}
		if err := o.do(o.preview); err != nil {
			t.Fatal(err)
		}
		if n := outcomes(ledgerStatus(t, o), admission.DispositionObserve); n != 1 || len(queuedCandidates(t, o)) != 0 {
			t.Fatalf("requested preview: %d observed, %d queued", n, len(queuedCandidates(t, o)))
		}
	})
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
	synctest.Test(t, func(t *testing.T) {
		p := withTestRegistry(t)
		f := newOwnerFixture(t)
		failing := errors.New("injected schedule failure")
		prev := scheduleLedger
		scheduleLedger = func(*store.AdmissionLedger, admission.ScheduleLimits) ([]admission.Pick, error) { return nil, failing }
		t.Cleanup(func() { scheduleLedger = prev })
		opts := previewOptions(f)
		opts.ScheduleEvery = time.Second
		o := f.start(opts)
		submitTo(t, o, p, "192.0.2.10", f.host.now())
		if err := o.do(o.drain); err != nil {
			t.Fatal(err)
		}
		time.Sleep(2 * time.Second)
		synctest.Wait()
		if s := o.Status().Owner; !strings.Contains(s.Error, failing.Error()) {
			t.Fatalf("owner error = %q", s.Error)
		}
		setOwnerHook(t, o, &scheduleLedger, prev)
		time.Sleep(time.Second)
		synctest.Wait()
		if s := o.Status().Owner; s.Error != "" || outcomes(ledgerStatus(t, o), admission.DispositionObserve) != 1 {
			t.Fatalf("after recovery: error %q, %d previews", s.Error, outcomes(ledgerStatus(t, o), admission.DispositionObserve))
		}
	})
}

// A preview turn that keeps failing is not retried every second, as a
// failing notice channel is not: the next two turns retry at once, each
// later attempt waits twice as long as the one before, up to an hour, and a
// turn that succeeds restores prompt retries.
func TestOwnerBacksOffAFailingPreviewTurn(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	mono := &fakeMono{now: time.Now()}
	var attempts atomic.Int64
	failing := func(*store.AdmissionLedger, admission.ScheduleLimits) ([]admission.Pick, error) {
		attempts.Add(1)
		return nil, errors.New("injected schedule failure")
	}
	prevMono, prevSchedule := monoNow, scheduleLedger
	monoNow, scheduleLedger = mono.read, failing
	t.Cleanup(func() { monoNow, scheduleLedger = prevMono, prevSchedule })
	o := f.start(previewOptions(f))
	turn := func() {
		t.Helper()
		if err := o.do(func() error { o.schedule(); return nil }); err != nil {
			t.Fatal(err)
		}
	}
	start := mono.read()
	var at []time.Duration
	for range 2 * 3600 {
		before := attempts.Load()
		turn()
		if attempts.Load() != before {
			at = append(at, mono.read().Sub(start))
		}
		mono.advance(time.Second)
	}
	var want []time.Duration
	for _, s := range []int{0, 1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096} {
		want = append(want, time.Duration(s)*time.Second)
	}
	if !reflect.DeepEqual(at, want) {
		t.Fatalf("attempts over two hours at %v, want %v", at, want)
	}
	if o.status().Owner.Error == "" {
		t.Fatal("a failing turn left no owner error")
	}
	// The attempt after 4096 s waits the hour cap, not 4096 s more.
	setOwnerHook(t, o, &scheduleLedger, func(l *store.AdmissionLedger, limits admission.ScheduleLimits) ([]admission.Pick, error) {
		attempts.Add(1)
		return prevSchedule(l, limits)
	})
	mono.advance(4096*time.Second + time.Hour - 2*time.Hour - time.Second)
	before := attempts.Load()
	turn()
	if attempts.Load() != before {
		t.Fatal("retried before the hour cap")
	}
	mono.advance(time.Second)
	turn()
	if attempts.Load() != before+1 || o.status().Owner.Error != "" {
		t.Fatalf("the hour-late retry: %d attempts, owner error %q", attempts.Load()-before, o.status().Owner.Error)
	}
	setOwnerHook(t, o, &scheduleLedger, failing)
	submitTo(t, o, p, "192.0.2.10", f.host.now())
	if err := o.do(o.drain); err != nil {
		t.Fatal(err)
	}
	before = attempts.Load()
	for range 4 {
		turn()
	}
	if got := attempts.Load() - before; got != 3 {
		t.Fatalf("a failure after a success made %d attempts in four turns, want 3", got)
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

func TestOwnerEndsAnInvalidPreviewWithoutStarvingWork(t *testing.T) {
	for _, tc := range []struct {
		name     string
		selected time.Duration
		fallback time.Duration
	}{
		{"unrepresentable selected expiry", time.Duration(1<<63 - 1), time.Hour},
		{"negative configured lifetime", 0, -time.Second},
		{"zero configured lifetime", 0, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			withTestRegistry(t)
			f := newOwnerFixture(t)
			opts := respondOptions(f)
			opts.ScheduleEvery = time.Hour
			fallback := time.Hour
			opts.Expiry = func(c admission.Candidate) time.Duration {
				if c.Key.Target.Key() == "ip:192.0.2.10" {
					return fallback
				}
				return time.Hour
			}
			prev := previewLimits
			previewLimits.Members = 1
			t.Cleanup(func() { previewLimits = prev })
			o := f.start(opts)
			for i, addr := range []string{"192.0.2.10", "192.0.2.11"} {
				sev, ttl := alert.High, time.Duration(0)
				if i == 0 {
					sev, ttl = alert.Critical, tc.selected
				}
				finding := sshFinding(f.host.now(), addr, sev)
				finding.SourceIP = addr
				e, err := o.Mint(finding, addr)
				if err != nil {
					t.Fatal(err)
				}
				if err = o.Respond(admission.KindBlockIP, e, 0, ttl); err != nil {
					t.Fatal(err)
				}
			}
			if err := o.do(o.drain); err != nil {
				t.Fatal(err)
			}
			var bad admission.CandidateID
			for _, c := range queuedCandidates(t, o) {
				if c.Key.Target.Key() == "ip:192.0.2.10" {
					bad, _ = c.ID()
				}
			}
			if bad == "" {
				t.Fatal("the invalid preview was not queued")
			}
			if err := o.do(func() error { fallback = tc.fallback; return nil }); err != nil {
				t.Fatal(err)
			}
			if err := o.Reload(); err != nil {
				t.Fatal(err)
			}
			for range 2 {
				if err := o.do(func() error { o.schedule(); return nil }); err != nil {
					t.Fatal(err)
				}
			}
			if err := o.do(func() error {
				c, err := o.ledger.Candidate(bad)
				if err != nil {
					return err
				}
				if c.State != admission.StateRefused || c.Reason != admission.ReasonInvalid || c.Attempts != 0 {
					t.Errorf("invalid preview = %+v", c)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			st := ledgerStatus(t, o)
			if outcomes(st, admission.DispositionObserve) != 1 || st.Ceiling.General.Used != 1 || len(queuedCandidates(t, o)) != 0 {
				t.Fatalf("observed %d, charges %d, queued %d", outcomes(st, admission.DispositionObserve), st.Ceiling.General.Used, len(queuedCandidates(t, o)))
			}
			if err := o.status().Owner.Error; err != "" {
				t.Fatalf("a handled refusal left an owner error: %s", err)
			}
		})
	}
}

func TestOwnerPreviewRetryKeepsItsReservedExpiry(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	opts := previewOptions(f)
	opts.ScheduleEvery = time.Hour
	o := f.start(opts)
	submitTo(t, o, p, "192.0.2.10", f.host.now())
	if err := o.do(o.drain); err != nil {
		t.Fatal(err)
	}
	queued := queuedCandidates(t, o)
	if len(queued) != 1 {
		t.Fatalf("queued = %+v", queued)
	}
	id, _ := queued[0].ID()
	expires := f.host.now().Add(time.Hour)
	if err := o.do(func() error {
		_, a, _, err := o.ledger.Reserve(id, admission.LaneGeneral, expires)
		if err != nil {
			return err
		}
		_, _, err = o.ledger.Finish(a.Attempt.ID, admission.DispositionFailed)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	f.host.advance(time.Second)
	if err := o.do(o.preview); err != nil {
		t.Fatal(err)
	}
	if err := o.do(func() error {
		c, err := o.ledger.Candidate(id)
		if err != nil {
			return err
		}
		if c.State != admission.StateObserved || c.Attempts != 2 || !c.ExpiresAt.Equal(expires) {
			t.Errorf("retry = %+v", c)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestOwnerReloadRecomputesThePreviewWake(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	f.host.set(func(h *fakeHost) { h.limit = 6 })
	mono := &fakeMono{now: time.Now()}
	prev := monoNow
	monoNow = mono.read
	t.Cleanup(func() { monoNow = prev })
	opts := previewOptions(f)
	opts.ScheduleEvery = time.Hour
	o := f.start(opts)
	submitTo(t, o, p, "192.0.2.10", f.host.now())
	submitTo(t, o, p, "192.0.2.11", f.host.now())
	if err := o.do(o.drain); err != nil {
		t.Fatal(err)
	}
	turn := func() {
		t.Helper()
		if err := o.do(func() error { o.schedule(); return nil }); err != nil {
			t.Fatal(err)
		}
	}
	turn()
	if n := outcomes(ledgerStatus(t, o), admission.DispositionObserve); n != 1 {
		t.Fatalf("first turn observed %d", n)
	}
	f.host.set(func(h *fakeHost) { h.limit = 2000 })
	if err := o.Reload(); err != nil {
		t.Fatal(err)
	}
	turn()
	f.host.advance(time.Minute)
	mono.advance(time.Minute)
	turn()
	if n := outcomes(ledgerStatus(t, o), admission.DispositionObserve); n != 2 {
		t.Fatalf("after the new ceiling earned credit: observed %d, want 2", n)
	}
}
