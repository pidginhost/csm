//go:build linux

package daemon

import (
	"context"
	"sync"

	"github.com/pidginhost/csm/internal/bpf"
	"github.com/pidginhost/csm/internal/obs"
	"github.com/pidginhost/csm/internal/queuehealth"
)

// placementWorkers bounds the goroutines blocked in handlePlacement, which
// waits up to its retry budget for a pending rename. A backend's reader
// never waits on them: a full output queue counts the event and hands it to
// overflow recovery.
const placementWorkers = 4

// startPlacementWorkers drains events with placementWorkers goroutines until
// ctx ends or events closes. resolve turns a queued item into the placement
// handle receives; false means the item placed nothing to check. The
// returned function waits for every worker to stop.
func startPlacementWorkers[T any](ctx context.Context, fm *FileMonitor, events <-chan queuehealth.Work[T], resolve func(T) (placementEvent, bool), handle func(placementEvent)) func() {
	var workers sync.WaitGroup
	for range placementWorkers {
		workers.Go(func() {
			for {
				select {
				case <-ctx.Done():
					return
				case work, ok := <-events:
					if !ok {
						return
					}
					processPlacement(fm, work, resolve, handle)
				}
			}
		})
	}
	return workers.Wait
}

// processPlacement contains a panic the way analyzeFileSafe does: one
// placement must not take the monitor down with it.
func processPlacement[T any](fm *FileMonitor, work queuehealth.Work[T], resolve func(T) (placementEvent, bool), handle func(placementEvent)) {
	var path string
	defer func() {
		if r := recover(); r != nil {
			fm.reportScannerPanic(path, r)
		}
	}()
	work.Process(func(item T) {
		ev, ok := resolve(item)
		if !ok {
			return
		}
		path = ev.Path
		handle(ev)
	})
}

// runPlacement runs b until the monitor stops. drainAndClose waits for it.
func (fm *FileMonitor) runPlacement(b bpf.Backend) {
	ctx, cancel := context.WithCancel(context.Background())
	fm.placementWG.Add(1)
	obs.Go("placement", func() {
		defer fm.placementWG.Done()
		defer cancel()
		obs.SafeGo("placement-stop-forward", func() {
			select {
			case <-fm.stopCh:
				cancel()
			case <-ctx.Done():
			}
		})
		b.Run(ctx)
	})
}
