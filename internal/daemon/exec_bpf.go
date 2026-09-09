//go:build linux && bpf

package daemon

import (
	"context"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/cilium/ebpf/link"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/bpf"
	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/config"
	bpfprog "github.com/pidginhost/csm/internal/daemon/exec_bpfprog"
	csmlog "github.com/pidginhost/csm/internal/log"
	"github.com/pidginhost/csm/internal/queuehealth"
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
		_ = objs.Close()
		return nil, fmt.Errorf("attach tracepoint: %w", err)
	}

	reader, err := bpf.NewReader[ExecEvent](objs.Events, decodeExecEvent)
	if err != nil {
		_ = tp.Close()
		_ = objs.Close()
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

func (e *execBPF) QueueStatuses(now time.Time) map[string]queuehealth.Status {
	return e.reader.QueueStatuses(now)
}

func (e *execBPF) Run(ctx context.Context) {
	stopReader := e.reader.Start(ctx)
	defer func() {
		_ = e.link.Close()
		stopReader()
		_ = e.objs.Close()
	}()

	errorsCh := e.reader.Errors()
	eventsCh := e.reader.Events()
	pcCache, pcEnr := ProcessCtx()
	for {
		select {
		case <-ctx.Done():
			return
		case err, ok := <-errorsCh:
			if !ok {
				errorsCh = nil
				continue
			}
			emitBPFReaderError(e.alertCh, "execution", err)
		case work, ok := <-eventsCh:
			if !ok {
				return
			}
			work.Process(func(ev ExecEvent) {
				e.count.Add(1)
				req := processctxRequestFromExec(ev)
				populateProcessCtxFromExec(pcCache, ev, req.StartedAt)
				if ev.PID != 0 {
					pcEnr.Enqueue(req)
				}
				for _, f := range checks.EvaluateExec(ev.UID, ev.PID, ev.Comm, ev.Filename, ev.ParentComm) {
					attachProcessCtxToExecFinding(pcCache, &f, ev)
					if !alert.TryEnqueue(e.alertCh, f) {
						csmlog.Warn("exec bpf: alert channel full, dropping finding")
					}
				}
			})
		}
	}
}
