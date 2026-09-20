package checks

import (
	"context"
	"slices"
	"testing"
	"testing/synctest"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/state"
)

// A heavy host-wide check walks accounts until its budget runs out and returns
// what it found so far. Dropping that slice because the deadline passed loses
// real detections: php_content timed out on every cycle for weeks and reported
// nothing at all. The timed-out check still stays out of the purge list, so
// keeping its partial findings can only add to the latest set.
func TestRunParallelKeepsPartialFindingsFromTimedOutCheck(t *testing.T) {
	st, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer func() { _ = st.Close() }()

	prevTimeout := timeoutForFunc
	t.Cleanup(func() { timeoutForFunc = prevTimeout })
	timeoutForFunc = func(string) time.Duration { return 25 * time.Millisecond }

	partial := alert.Finding{
		Check:    "obfuscated_php",
		Severity: alert.Critical,
		Message:  "obfuscated PHP found before the budget ran out",
	}

	checks := []namedCheck{
		{"php_content", func(ctx context.Context, _ *config.Config, _ *state.Store) []alert.Finding {
			found := []alert.Finding{partial}
			<-ctx.Done()
			return found
		}},
	}

	findings, purge := runParallel(&config.Config{}, st, checks, "test", false)

	if !containsFindingCheck(findings, "obfuscated_php") {
		t.Fatalf("partial findings from the timed-out check were dropped: %+v", findings)
	}
	if !containsFindingCheck(findings, "check_timeout") {
		t.Fatalf("timed-out check did not emit check_timeout warning: %+v", findings)
	}
	if slices.Contains(purge, "php_content") {
		t.Fatalf("timed-out php_content must stay out of the purge list: %v", purge)
	}
}

// A check that never returns has nothing to hand back, so the runner reports
// the timeout alone.
func TestRunParallelTimedOutCheckWithoutResultsReportsTimeoutOnly(t *testing.T) {
	st, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer func() { _ = st.Close() }()

	prevTimeout := timeoutForFunc
	t.Cleanup(func() { timeoutForFunc = prevTimeout })
	timeoutForFunc = func(string) time.Duration { return 25 * time.Millisecond }

	prevGrace := checkTimeoutDrainGrace
	t.Cleanup(func() { checkTimeoutDrainGrace = prevGrace })
	checkTimeoutDrainGrace = 25 * time.Millisecond

	wedged := make(chan struct{})
	t.Cleanup(func() { close(wedged) })
	checks := []namedCheck{
		{"php_content", func(ctx context.Context, _ *config.Config, _ *state.Store) []alert.Finding {
			<-ctx.Done()
			<-wedged
			return nil
		}},
	}

	findings, _ := runParallel(&config.Config{}, st, checks, "test", false)

	if len(findings) != 1 || findings[0].Check != "check_timeout" {
		t.Fatalf("expected only a check_timeout finding, got %+v", findings)
	}
}

func TestRunParallelCancellationDoesNotWaitForDrain(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		release := make(chan struct{})
		defer close(release)
		checks := []namedCheck{{"cancel_drain", func(context.Context, *config.Config, *state.Store) []alert.Finding {
			cancel()
			<-release
			return nil
		}}}
		start := time.Now()
		findings, purge := runParallelWithContext(ctx, &config.Config{}, nil, checks, "test", false)
		if len(findings) != 0 || len(purge) != 0 {
			t.Fatalf("canceled run published results: %v %v", findings, purge)
		}
		if elapsed := time.Since(start); elapsed != 0 {
			t.Fatalf("shutdown waited for drain: %v", elapsed)
		}
	})
}

func TestRunParallelDrainedDeadlineStillCountsLoss(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		previous := checkExecutions
		checkExecutions = newCheckExecutionMonitor()
		defer func() { checkExecutions = previous }()
		previousTimeout := timeoutForFunc
		timeoutForFunc = func(string) time.Duration { return time.Second }
		defer func() { timeoutForFunc = previousTimeout }()
		checks := []namedCheck{{"drain_loss", func(ctx context.Context, _ *config.Config, _ *state.Store) []alert.Finding {
			<-ctx.Done()
			time.Sleep(time.Millisecond)
			return []alert.Finding{{Check: "partial", Severity: alert.High}}
		}}}
		start := time.Now()
		findings, purge := runParallel(&config.Config{}, nil, checks, "test", false)
		synctest.Wait()
		status := CheckExecutionQueueStatus(time.Now())
		if status.DroppedTotal != 1 || status.InFlight != 0 || status.Depth != 0 {
			t.Fatalf("drained deadline accounting: %+v", status)
		}
		if len(findings) != 2 || !containsFindingCheck(findings, "partial") || !containsFindingCheck(findings, "check_timeout") || slices.Contains(purge, "drain_loss") {
			t.Fatalf("unexpected results: %v %v", findings, purge)
		}
		if time.Since(start) != time.Second+time.Millisecond {
			t.Fatal("result was drained more than once")
		}
	})
}
