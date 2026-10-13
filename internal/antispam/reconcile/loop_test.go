package reconcile

import (
	"context"
	"reflect"
	"sync"
	"testing"
	"testing/synctest"
	"time"
)

// recorder blocks each pass until released or canceled. Tests inspect it
// only after synctest.Wait, while the loop is durably blocked.
type recorder struct {
	mu      sync.Mutex
	passes  int
	reports []Outcome
	outcome Outcome
	release chan struct{}
}

func newRecorder() *recorder {
	return &recorder{release: make(chan struct{}, 1)}
}

func (r *recorder) pass(ctx context.Context) Outcome {
	r.mu.Lock()
	r.passes++
	out := r.outcome
	r.mu.Unlock()
	select {
	case <-r.release:
		return out
	case <-ctx.Done():
		return Outcome{Err: ctx.Err()}
	}
}

func (r *recorder) report(out Outcome) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.reports = append(r.reports, out)
}

func (r *recorder) check(t *testing.T, passes, reports int) {
	t.Helper()
	synctest.Wait()
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.passes != passes || len(r.reports) != reports {
		t.Fatalf("passes %d, reports %d; want %d, %d", r.passes, len(r.reports), passes, reports)
	}
}

// run is used inside a synctest bubble so neither startup nor shutdown
// depends on the host scheduler meeting a wall-clock deadline.
func run(t *testing.T, l *Loop) (cancel func()) {
	t.Helper()
	ctx, stop := context.WithCancel(context.Background())
	finished := make(chan struct{})
	go func() {
		l.Run(ctx)
		close(finished)
	}()
	cancel = func() {
		stop()
		synctest.Wait()
		select {
		case <-finished:
		default:
			t.Error("Run did not return after cancel")
		}
	}
	t.Cleanup(cancel)
	return cancel
}

func TestLoopPassesAtStartAndOnTrigger(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := newRecorder()
		l := NewLoop(r.pass, r.report)
		stop := run(t, l)
		r.check(t, 1, 0)
		r.release <- struct{}{}
		r.check(t, 1, 1)
		l.Trigger()
		r.check(t, 2, 1)
		r.release <- struct{}{}
		r.check(t, 2, 2)
		stop()
		r.check(t, 2, 2)
	})
}

// Triggers during a pass coalesce into one more pass, which reads the
// latest configuration after the running one ends (spec section 6.5).
func TestLoopCoalescesTriggersDuringAPass(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := newRecorder()
		cfg := desired(false)
		var seen []Desired
		l := NewLoop(func(ctx context.Context) Outcome {
			seen = append(seen, cfg)
			return r.pass(ctx)
		}, r.report)
		run(t, l)
		r.check(t, 1, 0)
		cfg = desired(true)
		l.Trigger()
		cfg.Settings.RejectScore++
		for range 100 {
			go l.Trigger()
		}
		r.check(t, 1, 0)
		// Even an overdue interval must not overlap the active pass.
		time.Sleep(2 * Interval)
		r.check(t, 1, 0)
		r.release <- struct{}{}
		r.check(t, 2, 1)
		if want := []Desired{desired(false), cfg}; !reflect.DeepEqual(seen, want) {
			t.Fatalf("configurations %+v, want %+v", seen, want)
		}
		r.release <- struct{}{}
		r.check(t, 2, 2)
	})
}

func TestLoopRetriesWhenAsked(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := newRecorder()
		r.outcome = Outcome{Retry: BusyRetry}
		l := NewLoop(r.pass, r.report)
		run(t, l)
		r.check(t, 1, 0)
		r.release <- struct{}{}
		r.check(t, 1, 1)
		if got := r.reports[0]; got.Retry != BusyRetry {
			t.Fatalf("reported retry %v, want %v", got.Retry, BusyRetry)
		}
		time.Sleep(BusyRetry - time.Nanosecond)
		r.check(t, 1, 1)
		time.Sleep(time.Nanosecond)
		r.check(t, 2, 1)
		// The retry outcome was captured at the start of this pass.
		r.outcome = Outcome{}
		r.release <- struct{}{}
		r.check(t, 2, 2)
		time.Sleep(BusyRetry)
		r.check(t, 3, 2)
		r.release <- struct{}{}
		r.check(t, 3, 3)
		time.Sleep(Interval - time.Nanosecond)
		r.check(t, 3, 3)
		time.Sleep(time.Nanosecond)
		r.check(t, 4, 3)
	})
}

func TestLoopRepeatsOnInterval(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := newRecorder()
		l := NewLoop(r.pass, r.report)
		run(t, l)
		r.check(t, 1, 0)
		for n := 1; n <= 3; n++ {
			r.release <- struct{}{}
			r.check(t, n, n)
			time.Sleep(Interval - time.Nanosecond)
			r.check(t, n, n)
			time.Sleep(time.Nanosecond)
			r.check(t, n+1, n)
		}
	})
}

func TestLoopTriggerNeverBlocks(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		l := NewLoop(func(context.Context) Outcome { return Outcome{} }, func(Outcome) {})
		done := make(chan struct{})
		go func() {
			for range 100 {
				l.Trigger()
			}
			close(done)
		}()
		synctest.Wait()
		select {
		case <-done:
		default:
			t.Fatal("Trigger blocked without a running loop")
		}
	})
}

// Stopping the daemon cancels the running pass, so a worker run returns
// instead of holding shutdown for its five minutes. Its report is kept.
func TestLoopCancelsTheRunningPass(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := newRecorder()
		l := NewLoop(r.pass, r.report)
		stop := run(t, l)
		r.check(t, 1, 0)
		stop()
		r.check(t, 1, 1)
		if got := r.reports[0].Err; got != context.Canceled {
			t.Fatalf("reported error %v, want context.Canceled", got)
		}
	})
}

func TestLoopDoesNotStartWithCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	passes, reports := 0, 0
	l := NewLoop(func(context.Context) Outcome {
		passes++
		return Outcome{}
	}, func(Outcome) { reports++ })
	l.Trigger()
	l.Run(ctx)
	if passes != 0 || reports != 0 {
		t.Fatalf("canceled loop ran %d passes and delivered %d reports", passes, reports)
	}
}

func TestLoopCancellationDiscardsPendingTrigger(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		// Repeat because select chooses randomly when both channels are ready.
		for range 100 {
			ctx, cancel := context.WithCancel(context.Background())
			passes := 0
			var reports []Outcome
			l := NewLoop(func(ctx context.Context) Outcome {
				passes++
				<-ctx.Done()
				return Outcome{Err: ctx.Err()}
			}, func(out Outcome) { reports = append(reports, out) })
			done := make(chan struct{})
			go func() {
				l.Run(ctx)
				close(done)
			}()
			synctest.Wait()
			l.Trigger()
			cancel()
			<-done
			if passes != 1 || len(reports) != 1 || reports[0].Err != context.Canceled {
				t.Fatalf("canceled loop ran %d passes and delivered reports %+v", passes, reports)
			}
		}
	})
}
