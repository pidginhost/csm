package checks

import (
	"context"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/state"
)

func blockingCheck(started chan<- struct{}, release <-chan struct{}) namedCheck {
	return namedCheck{name: "unit_blocking", fn: func(context.Context, *config.Config, *state.Store) []alert.Finding {
		close(started)
		<-release
		return nil
	}}
}

func waitStarted(t *testing.T, started <-chan struct{}) {
	t.Helper()
	select {
	case <-started:
	case <-time.After(10 * time.Second):
		t.Fatal("check never started")
	}
}

// The web UI shows whether a scan is running. Periodic tiers, CLI runs and
// scan jobs run here, not only scans the UI started.
func TestScanInProgressCoversTierRuns(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		runParallel(&config.Config{}, nil, []namedCheck{blockingCheck(started, release)}, "unit", true)
	}()
	waitStarted(t, started)
	if !ScanInProgress() {
		t.Error("ScanInProgress() = false while a tier run is working")
	}
	close(release)
	<-done
	if ScanInProgress() {
		t.Error("ScanInProgress() = true after the run finished")
	}
}

func TestScanInProgressCoversAccountScans(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		runAccountChecksBounded(context.Background(), &config.Config{}, nil, []namedCheck{blockingCheck(started, release)})
	}()
	waitStarted(t, started)
	if !ScanInProgress() {
		t.Error("ScanInProgress() = false while an account scan is working")
	}
	close(release)
	<-done
	if ScanInProgress() {
		t.Error("ScanInProgress() = true after the account scan finished")
	}
}

func TestScanInProgressBalancesNestedRuns(t *testing.T) {
	baseline := scansInFlight.Load()
	inner := namedCheck{name: "unit_nested", fn: func(context.Context, *config.Config, *state.Store) []alert.Finding {
		if got := scansInFlight.Load(); got != baseline+2 {
			t.Errorf("nested count = %d, want %d", got, baseline+2)
		}
		panic("test check panic")
	}}
	outer := namedCheck{name: "unit_outer", fn: func(ctx context.Context, cfg *config.Config, st *state.Store) []alert.Finding {
		findings := runAccountChecksBounded(ctx, cfg, st, []namedCheck{inner})
		if got := scansInFlight.Load(); got != baseline+1 {
			t.Errorf("outer count after nested panic = %d, want %d", got, baseline+1)
		}
		return findings
	}}
	findings, _ := runParallel(&config.Config{}, nil, []namedCheck{outer}, "unit", true)
	if len(findings) != 1 || findings[0].Check != "check_panic" {
		t.Fatalf("panic findings = %+v", findings)
	}
	if got := scansInFlight.Load(); got != baseline {
		t.Fatalf("final count = %d, want %d", got, baseline)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	runParallelWithContext(ctx, &config.Config{}, nil, []namedCheck{outer}, "unit", true)
	runAccountChecksBounded(ctx, &config.Config{}, nil, []namedCheck{inner})
	if got := scansInFlight.Load(); got != baseline {
		t.Fatalf("cancelled count = %d, want %d", got, baseline)
	}
}
