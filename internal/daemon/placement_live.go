package daemon

import (
	"context"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/bpf"
	"github.com/pidginhost/csm/internal/config"
	csmlog "github.com/pidginhost/csm/internal/log"
)

// StartPlacementMonitor starts the monitor for files renamed or hard-linked
// into fm's watch roots, chosen by detection.placement_backend: the BPF LSM
// hooks, else the fanotify directory-entry group ("legacy"), else none.
func StartPlacementMonitor(fm *FileMonitor, alertCh chan<- alert.Finding, cfg *config.Config) bpf.Backend {
	ctx := context.Background()
	mon := startLiveBackend("placement", cfg.Detection.PlacementBackend, alertCh,
		func() (bpf.Backend, error) { return tryStartPlacementBPFFn(ctx, fm) },
		func() bpf.Backend { return tryStartPlacementFIDFn(ctx, fm) })
	if mon == nil {
		csmlog.Warn("placement: no live backend; files renamed or hard-linked into watched trees, and directories moved into them, are checked only by the deep scan")
	}
	return mon
}

// startPlacementMonitor runs the placement backend beside the file monitor
// it feeds. The file monitor stops it before closing its analyzer queue.
func (d *Daemon) startPlacementMonitor(fm *FileMonitor) {
	mon := StartPlacementMonitor(fm, d.alertCh, d.cfg)
	if mon == nil {
		return
	}
	d.registerBackendQueues("bpf.placement", mon)
	fm.runPlacement(mon)
	csmlog.Info("placement: started", "backend", mon.Mode())
}

// Package-level indirections so tests can substitute fakes.
var (
	tryStartPlacementBPFFn = tryStartPlacementBPF
	tryStartPlacementFIDFn = tryStartPlacementFID
)

func tryStartPlacementBPF(ctx context.Context, fm *FileMonitor) (bpf.Backend, error) {
	p, err := startPlacementBPF(ctx, fm)
	if err != nil {
		return nil, err
	}
	return p, nil
}

// tryStartPlacementFID returns nil, never a typed nil, when the group cannot
// start, so the selection publishes none.
func tryStartPlacementFID(ctx context.Context, fm *FileMonitor) bpf.Backend {
	p, err := startPlacementFID(ctx, fm)
	if err != nil {
		csmlog.Info("placement: fanotify directory-entry group unavailable", "reason", err.Error())
		return nil
	}
	return p
}
