//go:build linux

package daemon

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/bpf"
	"github.com/pidginhost/csm/internal/config"
)

// The fanotify backend's queues reach status under the house BPF prefix, so
// an operator sees placement drops whichever backend runs.
func TestPlacementQueuesPublishUnderBPFPlacement(t *testing.T) {
	alerts := make(chan alert.Finding, 8)
	fm := placementTestMonitor(alerts)
	readFD, _ := fidPipe(t)
	oldBPF, oldFID := tryStartPlacementBPFFn, tryStartPlacementFIDFn
	t.Cleanup(func() { tryStartPlacementBPFFn, tryStartPlacementFIDFn = oldBPF, oldFID })
	tryStartPlacementBPFFn = func(context.Context, *FileMonitor) (bpf.Backend, error) { return nil, bpf.ErrNotBuilt }
	tryStartPlacementFIDFn = func(context.Context, *FileMonitor) bpf.Backend { return newPlacementFID(fm, readFD, nil) }

	d := &Daemon{cfg: &config.Config{}, alertCh: alerts}
	d.startPlacementMonitor(fm)
	defer func() {
		close(fm.stopCh)
		fm.drainAndClose()
	}()

	statuses := d.QueueStatuses()
	for _, row := range []string{"output", "create_settle", "kernel", "unresolved"} {
		if _, ok := statuses["bpf.placement."+row]; !ok {
			t.Errorf("status has no bpf.placement.%s row: %v", row, statuses)
		}
	}
}

// stopProbeBackend records whether the analyzer queue it feeds was still
// open when it stopped.
type stopProbeBackend struct {
	fm          *FileMonitor
	started     chan struct{}
	returned    atomic.Bool
	closedEarly atomic.Bool
}

func (b *stopProbeBackend) Mode() string       { return bpf.BackendLegacy }
func (b *stopProbeBackend) EventCount() uint64 { return 0 }
func (b *stopProbeBackend) Run(ctx context.Context) {
	close(b.started)
	<-ctx.Done()
	// A worker finishing its placement after the stop still admits into
	// the analyzer queue.
	time.Sleep(50 * time.Millisecond)
	select {
	case _, ok := <-b.fm.analyzerCh:
		if !ok {
			b.closedEarly.Store(true)
		}
	default:
	}
	b.returned.Store(true)
}

func TestPlacementBackendStopsBeforeAnalyzerQueueCloses(t *testing.T) {
	fm := placementTestMonitor(make(chan alert.Finding, 8))
	b := &stopProbeBackend{fm: fm, started: make(chan struct{})}
	fm.runPlacement(b)
	<-b.started

	close(fm.stopCh)
	fm.drainAndClose()

	if !b.returned.Load() {
		t.Fatal("analyzer queue closed while the placement backend was still running")
	}
	if b.closedEarly.Load() {
		t.Fatal("placement backend saw the analyzer queue closed before it stopped")
	}
}
