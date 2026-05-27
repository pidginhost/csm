//go:build linux && bpf

package daemon

import (
	"context"
	"fmt"
	"sync/atomic"

	"github.com/cilium/ebpf/link"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/bpf"
	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/config"
	bpfprog "github.com/pidginhost/csm/internal/daemon/exec_bpfprog"
	csmlog "github.com/pidginhost/csm/internal/log"
)

type execBPF struct {
	objs    *bpfprog.ExecObjects
	link    link.Link
	reader  *bpf.Reader[ExecEvent]
	alertCh chan<- alert.Finding
	cfg     *config.Config
	count   atomic.Uint64
}

func startExecBPF(_ context.Context, alertCh chan<- alert.Finding, cfg *config.Config) (*execBPF, error) {
	caps := bpf.Probe()
	if !caps.Tracepoint || !caps.Ringbuf {
		return nil, bpf.ErrUnsupported
	}

	objs := &bpfprog.ExecObjects{}
	if err := bpfprog.LoadExecObjects(objs, nil); err != nil {
		return nil, fmt.Errorf("load BPF objects: %w", err)
	}

	tp, err := link.Tracepoint("sched", "sched_process_exec", objs.CsmOnExec, nil)
	if err != nil {
		objs.Close()
		return nil, fmt.Errorf("attach tracepoint: %w", err)
	}

	reader, err := bpf.NewReader[ExecEvent](objs.Events, decodeExecEvent)
	if err != nil {
		_ = tp.Close()
		objs.Close()
		return nil, fmt.Errorf("ringbuf reader: %w", err)
	}

	return &execBPF{
		objs:    objs,
		link:    tp,
		reader:  reader,
		alertCh: alertCh,
		cfg:     cfg,
	}, nil
}

func (e *execBPF) Mode() string       { return "bpf" }
func (e *execBPF) EventCount() uint64 { return e.count.Load() }

func (e *execBPF) Run(ctx context.Context) {
	defer func() {
		_ = e.reader.Close()
		_ = e.link.Close()
		e.objs.Close()
	}()

	go e.reader.Run(ctx)
	pcCache, pcEnr := ProcessCtx()
	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-e.reader.Events():
			if !ok {
				return
			}
			e.count.Add(1)
			req := processctxRequestFromExec(ev)
			populateProcessCtxFromExec(pcCache, ev, req.StartedAt)
			if ev.PID != 0 {
				pcEnr.Enqueue(req)
			}
			for _, f := range checks.EvaluateExec(ev.UID, ev.PID, ev.Comm, ev.Filename, ev.ParentComm) {
				attachProcessCtxToExecFinding(pcCache, &f, ev)
				select {
				case e.alertCh <- f:
				default:
					csmlog.Warn("exec bpf: alert channel full, dropping finding")
				}
			}
		}
	}
}
