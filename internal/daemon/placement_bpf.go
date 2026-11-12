//go:build linux && bpf

package daemon

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync/atomic"
	"time"

	"github.com/cilium/ebpf/link"

	"github.com/pidginhost/csm/internal/bpf"
	bpfprog "github.com/pidginhost/csm/internal/daemon/placement_bpfprog"
	"github.com/pidginhost/csm/internal/queuehealth"
)

// placementSource is the part of bpf.Reader that Run consumes.
type placementSource interface {
	Start(context.Context) func()
	Events() <-chan queuehealth.Work[PlacementRawEvent]
	OnDrop(func(PlacementRawEvent))
	Errors() <-chan error
	QueueStatuses(time.Time) map[string]queuehealth.Status
}

type placementBPF struct {
	objs   *bpfprog.PlacementObjects
	links  []io.Closer
	source placementSource
	fm     *FileMonitor
	// handle is fm.handlePlacement; tests substitute a blocking or
	// panicking handler.
	handle func(placementEvent)
	// mounts is read once at startup. A mount moved later only costs
	// verification failures, never analysis of a different file.
	mounts []mountEntry
	count  atomic.Uint64
	// unresolved counts events dropped because their path was truncated or
	// had no whole-filesystem mount to join under; placementFromRaw also
	// raises a finding for them.
	unresolved *queuehealth.Tracker
}

func startPlacementBPF(_ context.Context, fm *FileMonitor) (*placementBPF, error) {
	caps := bpf.Probe()
	if !caps.LSMAttach || !caps.Ringbuf {
		return nil, bpf.ErrUnsupported
	}
	all, err := readMountinfo()
	if err != nil {
		return nil, fmt.Errorf("read mountinfo: %w", err)
	}
	mounts, roots, err := bpfPlacementMounts(all, fm.watchRoots)
	if err != nil {
		return nil, err
	}
	if len(mounts) == 0 {
		return nil, errors.New("no watch root is on a whole-filesystem mount")
	}

	objs := &bpfprog.PlacementObjects{}
	if err = bpfprog.LoadPlacementObjects(objs, nil); err != nil {
		return nil, fmt.Errorf("load BPF objects: %w", err)
	}
	p := &placementBPF{objs: objs, fm: fm, handle: fm.handlePlacement, mounts: mounts, unresolved: queuehealth.New(0, time.Minute)}
	if err = p.attach(); err != nil {
		p.closeKernel()
		return nil, err
	}
	reader, err := bpf.NewReader[PlacementRawEvent](objs.Events, objs.QueueStats, decodePlacementEvent)
	if err != nil {
		p.closeKernel()
		return nil, fmt.Errorf("ringbuf reader: %w", err)
	}
	p.source = reader
	// Only the backend that runs reports roots it cannot see; a failed
	// start falls back to one that may see them.
	fm.reportUncoveredPlacementRoots(all, mounts, roots)
	return p, nil
}

// attach fills the device filter before the hooks can fire.
func (p *placementBPF) attach() error {
	one := uint8(1)
	for _, m := range p.mounts {
		key := kernelDeviceID(m.Dev)
		if err := p.objs.DevsWatched.Update(&key, &one, 0); err != nil {
			return fmt.Errorf("update devs_watched: %w", err)
		}
	}
	rename, err := link.AttachLSM(link.LSMOptions{Program: p.objs.CsmInodeRename})
	if err != nil {
		return fmt.Errorf("attach lsm/inode_rename: %w", err)
	}
	p.links = append(p.links, rename)
	hardlink, err := link.AttachLSM(link.LSMOptions{Program: p.objs.CsmInodeLink})
	if err != nil {
		return fmt.Errorf("attach lsm/inode_link: %w", err)
	}
	p.links = append(p.links, hardlink)
	return nil
}

// closeKernel undoes a failed start, before any reader holds the ring.
func (p *placementBPF) closeKernel() {
	for _, l := range p.links {
		_ = l.Close()
	}
	p.links = nil
	_ = p.objs.Close()
}

func (p *placementBPF) Mode() string       { return "bpf" }
func (p *placementBPF) EventCount() uint64 { return p.count.Load() }

func (p *placementBPF) QueueStatuses(now time.Time) map[string]queuehealth.Status {
	states := p.source.QueueStatuses(now)
	states["unresolved"] = p.unresolved.Snapshot(now)
	return states
}

func (p *placementBPF) Run(ctx context.Context) {
	p.source.OnDrop(p.recoverDropped)
	stopReader := p.source.Start(ctx)
	waitWorkers := startPlacementWorkers(ctx, p.fm, p.source.Events(), p.resolve, p.handle)
	// The reader closes its error channel once ctx ends and it has stopped.
	for err := range p.source.Errors() {
		emitBPFReaderError(p.fm.alertCh, "placement", err)
	}
	// Consumers stop before the hooks detach, and both before the reader
	// discards what is left.
	waitWorkers()
	for _, l := range p.links {
		_ = l.Close()
	}
	stopReader()
	_ = p.objs.Close()
}

func (p *placementBPF) resolve(raw PlacementRawEvent) []placementEvent {
	p.count.Add(1)
	ev, ok := p.fm.placementFromRaw(raw, p.mounts, raw.At)
	if !ok {
		p.unresolved.Lose(time.Now(), 1)
		return nil
	}
	events := []placementEvent{ev}
	for _, m := range p.mounts {
		path, ok := resolvePlacementPath(ev.Dev, raw.Components, []mountEntry{m})
		if !ok || path == ev.Path {
			continue
		}
		alias := ev
		alias.Path = path
		events = append(events, alias)
	}
	return events
}

// recoverDropped runs on the reader goroutine for an event the full output
// queue refused. Resolving a path is a join, cheap enough to do there.
func (p *placementBPF) recoverDropped(raw PlacementRawEvent) {
	for _, ev := range p.resolve(raw) {
		p.fm.recoverDroppedPlacement(ev)
	}
}
