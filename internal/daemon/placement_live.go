package daemon

import (
	"context"
	"errors"
	"strings"

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
	var bpfErr, fidErr error
	mon := startLiveBackend("placement", cfg.Detection.PlacementBackend, alertCh,
		func() (bpf.Backend, error) {
			b, err := tryStartPlacementBPFFn(ctx, fm)
			bpfErr = err
			return b, err
		},
		func() bpf.Backend {
			b, err := tryStartPlacementFIDFn(ctx, fm)
			if err != nil {
				fidErr = err
				csmlog.Info("placement: fanotify directory-entry group unavailable", "reason", err.Error())
				return nil
			}
			return b
		})
	if mon != nil {
		return mon
	}
	// A kernel without support is expected on older hosts and shows in
	// status; an unexpected failure is a finding. Both ran only under auto.
	switch {
	case bpfErr != nil && fidErr != nil:
		if !placementUnsupported(bpfErr, fidErr) {
			emitBPFUnavailableFinding(alertCh, "placement", bpf.BackendAuto, "", errors.Join(bpfErr, fidErr))
		}
	case fidErr != nil:
		if !errors.Is(fidErr, errPlacementFIDUnsupported) {
			emitBPFUnavailableFinding(alertCh, "placement", bpf.BackendLegacy, "", fidErr)
		}
	}
	// An explicit bpf choice already warned.
	if !strings.EqualFold(strings.TrimSpace(cfg.Detection.PlacementBackend), bpf.BackendBPF) {
		csmlog.Warn("placement: no live backend; files renamed or hard-linked into watched trees, and directories moved into them, are checked only by the deep scan")
	}
	return nil
}

// errPlacementFIDUnsupported marks a kernel that cannot report directory
// entries through fanotify at all.
var errPlacementFIDUnsupported = errors.New("kernel lacks fanotify directory-entry events")

func placementUnsupported(bpfErr, fidErr error) bool {
	return (errors.Is(bpfErr, bpf.ErrUnsupported) || errors.Is(bpfErr, bpf.ErrNotBuilt)) &&
		errors.Is(fidErr, errPlacementFIDUnsupported)
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

// tryStartPlacementFID returns nil, never a typed nil, with the error.
func tryStartPlacementFID(ctx context.Context, fm *FileMonitor) (bpf.Backend, error) {
	p, err := startPlacementFID(ctx, fm)
	if err != nil {
		return nil, err
	}
	return p, nil
}
