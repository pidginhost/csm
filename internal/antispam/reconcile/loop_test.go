package reconcile

import (
	"context"
	"sync"
	"testing"
	"time"
)

// recorder counts passes and blocks each one until released, so tests can
// trigger while a pass runs.
type recorder struct {
	mu       sync.Mutex
	passes   int
	reported int
	outcome  Outcome
	started  chan int
	release  chan struct{}
}

func newRecorder() *recorder {
	return &recorder{started: make(chan int, 16), release: make(chan struct{}, 16)}
}

func (r *recorder) pass(context.Context) Outcome {
	r.mu.Lock()
	r.passes++
	n, out := r.passes, r.outcome
	r.mu.Unlock()
	r.started <- n
	<-r.release
	return out
}

func (r *recorder) report(Outcome) {
	r.mu.Lock()
	r.reported++
	r.mu.Unlock()
}

func (r *recorder) count() (int, int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.passes, r.reported
}

func waitPass(t *testing.T, r *recorder, want int) {
	t.Helper()
	select {
	case n := <-r.started:
		if n != want {
			t.Fatalf("pass %d started, want %d", n, want)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("pass %d did not start", want)
	}
}

func run(t *testing.T, l *Loop) (cancel func()) {
	t.Helper()
	ctx, stop := context.WithCancel(context.Background())
	finished := make(chan struct{})
	go func() {
		l.Run(ctx)
		close(finished)
	}()
	return func() {
		stop()
		select {
		case <-finished:
		case <-time.After(5 * time.Second):
			t.Fatal("Run did not return after cancel")
		}
	}
}

func TestLoopPassesAtStartAndOnTrigger(t *testing.T) {
	r := newRecorder()
	l := NewLoop(r.pass, r.report)
	l.interval = time.Hour
	stop := run(t, l)
	waitPass(t, r, 1)
	r.release <- struct{}{}
	l.Trigger()
	waitPass(t, r, 2)
	r.release <- struct{}{}
	stop()
	if passes, reported := r.count(); passes != 2 || reported != 2 {
		t.Fatalf("passes %d, reported %d", passes, reported)
	}
}

// Triggers during a pass coalesce into one more pass, which reads the
// latest configuration after the running one ends (spec section 6.5).
func TestLoopCoalescesTriggersDuringAPass(t *testing.T) {
	r := newRecorder()
	l := NewLoop(r.pass, r.report)
	l.interval = time.Hour
	stop := run(t, l)
	waitPass(t, r, 1)
	l.Trigger()
	l.Trigger()
	l.Trigger()
	r.release <- struct{}{}
	waitPass(t, r, 2)
	r.release <- struct{}{}
	select {
	case n := <-r.started:
		t.Fatalf("pass %d ran for coalesced triggers", n)
	case <-time.After(100 * time.Millisecond):
	}
	stop()
}

func TestLoopRetriesWhenAsked(t *testing.T) {
	r := newRecorder()
	r.outcome = Outcome{Retry: 10 * time.Millisecond}
	l := NewLoop(r.pass, r.report)
	l.interval = time.Hour
	stop := run(t, l)
	waitPass(t, r, 1)
	r.release <- struct{}{}
	waitPass(t, r, 2)
	r.release <- struct{}{}
	stop()
}

func TestLoopRepeatsOnInterval(t *testing.T) {
	r := newRecorder()
	l := NewLoop(r.pass, r.report)
	l.interval = 10 * time.Millisecond
	stop := run(t, l)
	for n := 1; n <= 3; n++ {
		waitPass(t, r, n)
		r.release <- struct{}{}
	}
	stop()
}

func TestLoopTriggerNeverBlocks(t *testing.T) {
	l := NewLoop(func(context.Context) Outcome { return Outcome{} }, func(Outcome) {})
	done := make(chan struct{})
	go func() {
		for range 100 {
			l.Trigger()
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Trigger blocked without a running loop")
	}
}

// Stopping the daemon cancels the running pass, so a worker run returns
// instead of holding shutdown for its five minutes.
func TestLoopCancelsTheRunningPass(t *testing.T) {
	started := make(chan struct{})
	l := NewLoop(func(ctx context.Context) Outcome {
		close(started)
		<-ctx.Done()
		return Outcome{Err: ctx.Err()}
	}, func(Outcome) {})
	stop := run(t, l)
	<-started
	stop()
}
