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
