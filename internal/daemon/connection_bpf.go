//go:build linux && bpf

package daemon

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync/atomic"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/bpf"
	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/config"
	bpfprog "github.com/pidginhost/csm/internal/daemon/connection_bpfprog"
	csmlog "github.com/pidginhost/csm/internal/log"
	"github.com/pidginhost/csm/internal/platform"
)

type connectionBPF struct {
	objs    *bpfprog.ConnectionObjects
	link4   link.Link
	link6   link.Link
	reader  *bpf.Reader[ConnectionEvent]
	alertCh chan<- alert.Finding
	cfg     *config.Config
	count   atomic.Uint64
}

// startConnectionBPF loads the BPF objects, attaches connect4 + connect6 to
// the unified cgroup root, and prepares the ringbuf reader. Returns
// bpf.ErrUnsupported when the kernel cap probe says cgroup-sock or ringbuf
// is unusable, so the coordinator can fall through to the legacy poller
// cleanly.
func startConnectionBPF(_ context.Context, alertCh chan<- alert.Finding, cfg *config.Config) (*connectionBPF, error) {
	caps := bpf.Probe()
	if !caps.CgroupSock || !caps.Ringbuf {
		return nil, bpf.ErrUnsupported
	}

	cgroupPath, err := unifiedCgroupRoot()
	if err != nil {
		return nil, fmt.Errorf("cgroup v2 root: %w", err)
	}

	objs := &bpfprog.ConnectionObjects{}
	if err := bpfprog.LoadConnectionObjects(objs, nil); err != nil {
		return nil, fmt.Errorf("load BPF objects: %w", err)
	}

	l4, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cgroupPath,
		Attach:  ebpf.AttachCGroupInet4Connect,
		Program: objs.CsmConnect4,
	})
	if err != nil {
		objs.Close()
		return nil, fmt.Errorf("attach connect4: %w", err)
	}
	l6, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cgroupPath,
		Attach:  ebpf.AttachCGroupInet6Connect,
		Program: objs.CsmConnect6,
	})
	if err != nil {
		_ = l4.Close()
		objs.Close()
		return nil, fmt.Errorf("attach connect6: %w", err)
	}

	reader, err := bpf.NewReader[ConnectionEvent](objs.Events, decodeConnectionEvent)
	if err != nil {
		_ = l4.Close()
		_ = l6.Close()
		objs.Close()
		return nil, fmt.Errorf("ringbuf reader: %w", err)
	}

	return &connectionBPF{
		objs:    objs,
		link4:   l4,
		link6:   l6,
		reader:  reader,
		alertCh: alertCh,
		cfg:     cfg,
	}, nil
}

func (c *connectionBPF) Mode() string       { return "bpf" }
func (c *connectionBPF) EventCount() uint64 { return c.count.Load() }

func (c *connectionBPF) Run(ctx context.Context) {
	defer func() {
		_ = c.reader.Close()
		_ = c.link4.Close()
		_ = c.link6.Close()
		c.objs.Close()
	}()

	go c.reader.Run(ctx)
	pcCache, pcEnr := ProcessCtx()
	// Resolve MTA identities once; platform.Detect() probes the FS so
	// keep it out of the per-event hot path.
	mta := platform.LocalMTAIdentities(platform.Detect())
	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-c.reader.Events():
			if !ok {
				return
			}
			c.count.Add(1)
			user := checks.LookupUser(ev.UID)
			for _, finding := range evaluateConnectionEvent(c.cfg, mta, ev, user) {
				attachProcessCtxToFinding(pcCache, pcEnr, &finding, ev)
				select {
				case c.alertCh <- finding:
				default:
					csmlog.Warn("connection bpf: alert channel full, dropping finding")
				}
			}
		}
	}
}

// unifiedCgroupRoot returns the path to the cgroup v2 unified hierarchy
// root, or an error if no cgroup v2 mount is found. The presence of
// cgroup.controllers under the path is the standard cgroup v2 marker;
// cgroup v1 mounts at /sys/fs/cgroup do not have it.
func unifiedCgroupRoot() (string, error) {
	for _, p := range []string{"/sys/fs/cgroup", "/sys/fs/cgroup/unified"} {
		st, err := os.Stat(p)
		if err != nil || !st.IsDir() {
			continue
		}
		if _, err := os.Stat(p + "/cgroup.controllers"); err == nil {
			return p, nil
		}
	}
	return "", errors.New("no cgroup v2 unified hierarchy found")
}
