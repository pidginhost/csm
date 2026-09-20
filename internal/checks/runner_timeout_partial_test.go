package checks

import (
	"context"
	"slices"
	"testing"
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
