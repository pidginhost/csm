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

// A check that ends because the whole scan was cancelled is not a check that
// timed out. Reporting it as check_timeout persisted one bogus warning per
// remaining check every time an operator cancelled an account scan.
func TestRunAccountScanCheckCancelledParentEmitsNoTimeout(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	started := make(chan struct{}, 1)
	slow := namedCheck{"slow", func(ctx context.Context, _ *config.Config, _ *state.Store) []alert.Finding {
		started <- struct{}{}
		<-ctx.Done()
		return nil
	}}
	got := runAccountScanCheck(ctx, slow, &config.Config{}, nil, time.Minute)
	for _, f := range got {
		if f.Check == "check_timeout" {
			t.Fatalf("cancelled scan reported %q as a timeout", f.Message)
		}
	}
	select {
	case <-started:
		t.Fatal("check function started after its parent context was already canceled")
	case <-time.After(100 * time.Millisecond):
	}
}

// Once the scan is cancelled, checks still waiting for a worker slot must not
// start at all; the slot wait used to ignore the context, so every queued
// check still ran (and then reported a timeout) after the operator cancelled.
func TestRunAccountChecksBoundedSkipsQueuedChecksAfterCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(withScanBudget(context.Background(), 2))
	var started atomic.Int32
	release := make(chan struct{})
	blocker := func(ctx context.Context, _ *config.Config, _ *state.Store) []alert.Finding {
		started.Add(1)
		<-release
		return nil
	}
	var checks []namedCheck
	for i := 0; i < 8; i++ {
		checks = append(checks, namedCheck{"blocker", blocker})
	}

	done := make(chan []alert.Finding, 1)
	go func() { done <- runAccountChecksBounded(ctx, &config.Config{}, nil, checks) }()
	for started.Load() < 2 {
		time.Sleep(time.Millisecond)
	}
	cancel()
	close(release)

	select {
	case findings := <-done:
		if n := started.Load(); n != 2 {
			t.Fatalf("%d checks started, want only the 2 that held a slot before the cancel", n)
		}
		for _, f := range findings {
			if f.Check == "check_timeout" {
				t.Fatalf("cancelled scan reported a timeout: %s", f.Message)
			}
		}
	case <-time.After(5 * time.Second):
		t.Fatal("runner did not return after cancel")
	}
}
