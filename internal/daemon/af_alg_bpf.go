//go:build linux && bpf

package daemon

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/cilium/ebpf/link"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/bpf"
	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/config"
	bpfprog "github.com/pidginhost/csm/internal/daemon/af_alg_bpfprog"
	csmlog "github.com/pidginhost/csm/internal/log"
)

type afAlgBPF struct {
	objs    *bpfprog.AFAlgObjects
	link    link.Link
	reader  *bpf.Reader[checks.AFAlgEvent]
	alertCh chan<- alert.Finding
	cfg     *config.Config
	count   atomic.Uint64
}

// tryStartBPFLSM loads and attaches the AF_ALG socket_create deny program
// on hosts where the kernel supports BPF LSM, then returns a backend that
// emits findings and runs reactToAFAlgEvent for each ringbuf event. Returns
// bpf.ErrUnsupported when the kernel cannot run the program; the
// coordinator then falls back to the audit-log listener.
func tryStartBPFLSM(_ context.Context, alertCh chan<- alert.Finding, cfg *config.Config) (AFAlgLiveMonitor, error) {
	caps := bpf.Probe()
	if !caps.LSMAttach || !caps.Ringbuf {
		return nil, bpf.ErrUnsupported
	}

	objs := &bpfprog.AFAlgObjects{}
	if err := bpfprog.LoadAFAlgObjects(objs, nil); err != nil {
		return nil, fmt.Errorf("load AF_ALG BPF objects: %w", err)
	}

	l, err := link.AttachLSM(link.LSMOptions{Program: objs.CsmBlockAfAlg})
	if err != nil {
		objs.Close()
		return nil, fmt.Errorf("attach lsm/socket_create: %w", err)
	}

	reader, err := bpf.NewReader[checks.AFAlgEvent](objs.Events, decodeAFAlgEvent)
	if err != nil {
		_ = l.Close()
		objs.Close()
		return nil, fmt.Errorf("ringbuf reader: %w", err)
	}

	return &afAlgBPF{
		objs:    objs,
		link:    l,
		reader:  reader,
		alertCh: alertCh,
		cfg:     cfg,
	}, nil
}

func (a *afAlgBPF) Mode() string       { return "bpf-lsm" }
func (a *afAlgBPF) EventCount() uint64 { return a.count.Load() }

func (a *afAlgBPF) Run(ctx context.Context) {
	defer func() {
		_ = a.reader.Close()
		_ = a.link.Close()
		a.objs.Close()
	}()

	go a.reader.Run(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-a.reader.Events():
			if !ok {
				return
			}
			a.count.Add(1)
			a.handle(ev)
		}
	}
}

func (a *afAlgBPF) handle(ev checks.AFAlgEvent) {
	finding := alert.Finding{
		Severity:  alert.Critical,
		Check:     "af_alg_socket_use",
		Message:   fmt.Sprintf("AF_ALG socket opened by uid=%s exe=%s", ev.UID, ev.Exe),
		Timestamp: time.Now(),
		Details: fmt.Sprintf(
			"Live BPF LSM detection: uid=%s comm=%q exe=%q pid=%s\n"+
				"AF_ALG is essentially never used by cPanel/PHP workloads. This is\n"+
				"the kernel-level exploit signature for CVE-2026-31431 (\"Copy Fail\").\n"+
				"This call was REFUSED by the kernel-side BPF LSM program; investigate\n"+
				"the offending process immediately.",
			ev.UID, ev.Comm, ev.Exe, ev.PID,
		),
	}
	select {
	case a.alertCh <- finding:
	default:
		csmlog.Warn("af_alg bpf: alert channel full; finding dropped", "uid", ev.UID, "exe", ev.Exe)
	}
	reactToAFAlgEvent(a.cfg, ev)
}

// decodeAFAlgEvent unpacks the BPF struct af_alg_event into the userspace
// AFAlgEvent that reactToAFAlgEvent already consumes. PPID and ParentComm
// are decoded but not propagated to the userspace shape; they remain in
// the BPF event so future enrichment lands without a wire-format change.
func decodeAFAlgEvent(b []byte) (checks.AFAlgEvent, error) {
	const minSize = 4 + 4 + 4 + 16 + 16 + 256
	if len(b) < minSize {
		return checks.AFAlgEvent{}, errors.New("af_alg event short buffer")
	}
	uid := binary.LittleEndian.Uint32(b[0:4])
	pid := binary.LittleEndian.Uint32(b[4:8])
	// b[8:12] = ppid, b[28:44] = parent_comm; both retained kernel-side, dropped here.
	comm := nullTerm(b[12:28])
	exe := nullTerm(b[44 : 44+256])
	return checks.AFAlgEvent{
		PID:  strconv.FormatUint(uint64(pid), 10),
		UID:  strconv.FormatUint(uint64(uid), 10),
		Comm: comm,
		Exe:  exe,
	}, nil
}
