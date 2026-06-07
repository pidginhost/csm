package checks

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/state"
)

// A periodic scan must abort promptly when the daemon cancels the shutdown
// context, instead of running the whole tier to completion and stalling the
// shutdown drain. Without the wiring, runParallel derives its scan context
// from context.Background() and the cancel has no effect, so a check that
// honours cancellation still blocks until its own per-check timeout fires.
func TestRunParallelAbortsOnShutdownCancel(t *testing.T) {
	// Pin a long per-check budget so the per-check timeout cannot mask or
	// race the shutdown-cancellation path under test.
	prevTimeout := timeoutForFunc
	timeoutForFunc = func(string) time.Duration { return time.Minute }
	t.Cleanup(func() { timeoutForFunc = prevTimeout })

	ctx, cancel := context.WithCancel(context.Background())

	started := make(chan struct{})
	blocker := namedCheck{
		name: "shutdown_blocker_test",
		fn: func(c context.Context, _ *config.Config, _ *state.Store) []alert.Finding {
			close(started)
			<-c.Done() // honour cancellation
			return nil
		},
	}

	type result struct {
		findings []alert.Finding
		purge    []string
	}
	out := make(chan result, 1)
	go func() {
		findings, purge := runParallelWithContext(ctx, &config.Config{}, nil, []namedCheck{blocker}, "test", false)
		out <- result{findings: findings, purge: purge}
	}()

	<-started
	cancel()

	select {
	case got := <-out:
		if len(got.purge) != 0 {
			t.Fatalf("shutdown-aborted scan returned purge checks: %v", got.purge)
		}
		for _, f := range got.findings {
			if f.Check == "check_timeout" {
				t.Errorf("shutdown abort must not emit a check_timeout finding: %+v", f)
			}
		}
	case <-time.After(3 * time.Second):
		t.Fatal("runParallel did not abort after the shutdown context was cancelled")
	}
}

// One-shot callers (CLI, control socket) never set a shutdown context, so a
// scan must complete normally against the default Background parent.
func TestRunParallelCompletesWithoutShutdownContext(t *testing.T) {
	ran := make(chan struct{}, 1)
	c := namedCheck{
		name: "noop_completes_test",
		fn: func(context.Context, *config.Config, *state.Store) []alert.Finding {
			ran <- struct{}{}
			return nil
		},
	}

	done := make(chan struct{})
	go func() {
		_, _ = runParallel(&config.Config{}, nil, []namedCheck{c}, "test", false)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("runParallel stalled with the default Background parent context")
	}
	select {
	case <-ran:
	default:
		t.Fatal("check did not run under the default parent context")
	}
}

func TestRunParallelDoesNotStartQueuedChecksAfterCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	var budgetCalls atomic.Int64
	prevTimeout := timeoutForFunc
	timeoutForFunc = func(string) time.Duration {
		budgetCalls.Add(1)
		return time.Minute
	}
	t.Cleanup(func() { timeoutForFunc = prevTimeout })

	started := make(chan struct{}, 5)
	checks := make([]namedCheck, 0, 20)
	for i := 0; i < cap(checks); i++ {
		checks = append(checks, namedCheck{
			name: "shutdown_blocker_test",
			fn: func(c context.Context, _ *config.Config, _ *state.Store) []alert.Finding {
				select {
				case started <- struct{}{}:
				default:
				}
				<-c.Done()
				return nil
			},
		})
	}

	done := make(chan struct{})
	go func() {
		_, _ = runParallelWithContext(ctx, &config.Config{}, nil, checks, "test", false)
		close(done)
	}()

	for i := 0; i < 5; i++ {
		select {
		case <-started:
		case <-time.After(3 * time.Second):
			t.Fatal("blocking checks did not start")
		}
	}

	cancel()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("runParallel did not return after cancellation")
	}

	if got := budgetCalls.Load(); got != 5 {
		t.Fatalf("started check count after cancellation = %d, want 5", got)
	}
}
