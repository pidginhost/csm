package checks

import (
	"context"
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

	prevParent := scanShutdownContext()
	ctx, cancel := context.WithCancel(context.Background())
	SetScanShutdownContext(ctx)
	t.Cleanup(func() { SetScanShutdownContext(prevParent) })

	started := make(chan struct{})
	blocker := namedCheck{
		name: "shutdown_blocker_test",
		fn: func(c context.Context, _ *config.Config, _ *state.Store) []alert.Finding {
			close(started)
			<-c.Done() // honour cancellation
			return nil
		},
	}

	out := make(chan []alert.Finding, 1)
	go func() {
		findings, _ := runParallel(&config.Config{}, nil, []namedCheck{blocker}, "test", false)
		out <- findings
	}()

	<-started
	cancel()

	select {
	case findings := <-out:
		for _, f := range findings {
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
	SetScanShutdownContext(context.Background())
	t.Cleanup(func() { SetScanShutdownContext(context.Background()) })

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
