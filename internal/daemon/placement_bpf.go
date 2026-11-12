//go:build linux && bpf

package daemon

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cilium/ebpf/link"

	"github.com/pidginhost/csm/internal/bpf"
	bpfprog "github.com/pidginhost/csm/internal/daemon/placement_bpfprog"
	csmlog "github.com/pidginhost/csm/internal/log"
	"github.com/pidginhost/csm/internal/queuehealth"
)

// placementWorkers bounds the goroutines blocked in handlePlacement, which
// waits up to its retry budget for a pending rename. The ring reader never
// waits on them: a full output queue drops and counts the event.
const placementWorkers = 4

type placementBPF struct {
	objs   *bpfprog.PlacementObjects
	links  []io.Closer
	reader *bpf.Reader[PlacementRawEvent]
	fm     *FileMonitor
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
	mounts := placementMounts(all, fm.watchRoots)
	for _, r := range fm.watchRoots {
		if !slices.ContainsFunc(mounts, func(m mountEntry) bool { return m.Dev == r.device }) {
			csmlog.Warn("placement bpf: watch root has no whole-filesystem mount; placements there are not reported", "root", r.path)
		}
	}
	if len(mounts) == 0 {
		return nil, errors.New("no watch root is on a whole-filesystem mount")
	}

	objs := &bpfprog.PlacementObjects{}
	if err = bpfprog.LoadPlacementObjects(objs, nil); err != nil {
		return nil, fmt.Errorf("load BPF objects: %w", err)
	}
	p := &placementBPF{objs: objs, fm: fm, mounts: mounts, unresolved: queuehealth.New(0, time.Minute)}
	if err = p.attach(); err != nil {
		p.closeKernel()
		return nil, err
	}
	reader, err := bpf.NewReader[PlacementRawEvent](objs.Events, objs.QueueStats, decodePlacementEvent)
	if err != nil {
		p.closeKernel()
		return nil, fmt.Errorf("ringbuf reader: %w", err)
	}
	p.reader = reader
	return p, nil
}

func readMountinfo() ([]mountEntry, error) {
	f, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return parseMountinfo(f)
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
	states := p.reader.QueueStatuses(now)
	states["unresolved"] = p.unresolved.Snapshot(now)
	return states
}

func (p *placementBPF) Run(ctx context.Context) {
	stopReader := p.reader.Start(ctx)
	var workers sync.WaitGroup
	for range placementWorkers {
		workers.Add(1)
		go func() {
			defer workers.Done()
			p.consume(ctx)
		}()
	}
	// The reader closes its error channel once ctx ends and it has stopped.
	for err := range p.reader.Errors() {
		emitBPFReaderError(p.fm.alertCh, "placement", err)
	}
	// Consumers stop before the hooks detach, and both before the reader
	// discards what is left.
	workers.Wait()
	for _, l := range p.links {
		_ = l.Close()
	}
	stopReader()
	_ = p.objs.Close()
}

func (p *placementBPF) consume(ctx context.Context) {
	events := p.reader.Events()
	for {
		select {
		case <-ctx.Done():
			return
		case work, ok := <-events:
			if !ok {
				return
			}
			p.process(work)
		}
	}
}

// process contains a panic the way analyzeFileSafe does: one placement must
// not take the monitor down with it.
func (p *placementBPF) process(work queuehealth.Work[PlacementRawEvent]) {
	var path string
	defer func() {
		if r := recover(); r != nil {
			p.fm.reportScannerPanic(path, r)
		}
	}()
	work.Process(func(raw PlacementRawEvent) {
		p.count.Add(1)
		ev, ok := p.fm.placementFromRaw(raw, p.mounts, time.Now())
		if !ok {
			p.unresolved.Lose(time.Now(), 1)
			return
		}
		path = ev.Path
		p.fm.handlePlacement(ev)
	})
}
