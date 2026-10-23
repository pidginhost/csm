package daemon

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/config"
	csmlog "github.com/pidginhost/csm/internal/log"
	"github.com/pidginhost/csm/internal/queuehealth"
)

// docrootExecQueueSize bounds the process starts waiting for inspection.
const docrootExecQueueSize = 1024

// docrootExecRefreshInterval is how often the document-root set is resolved
// again, so added and removed accounts are picked up without a restart.
const docrootExecRefreshInterval = 5 * time.Minute

// inspectDocrootExec is indirected so tests can observe what the worker asks.
var inspectDocrootExec = checks.InspectDocrootExec

// docrootExecMonitor judges process starts whose program may live in a
// document root. The exec event loop only filters and queues; reading and
// scanning a program happens on the monitor's own goroutine, so a slow scan
// never holds up other exec events. A start that does not fit the queue is
// counted in its health row, which reports the loss like any other
// protection queue. The program file is still read by the scheduled deep
// scan, and a process that keeps running is judged by the periodic check.
type docrootExecMonitor struct {
	cfg     *config.Config
	alertCh chan<- alert.Finding
	roots   atomic.Pointer[checks.DocrootIndex]
	queue   *queuehealth.Channel[ExecEvent]
}

func newDocrootExecMonitor(cfg *config.Config, alertCh chan<- alert.Finding) *docrootExecMonitor {
	m := &docrootExecMonitor{
		cfg:     cfg,
		alertCh: alertCh,
		queue:   queuehealth.NewChannel[ExecEvent](docrootExecQueueSize, time.Minute),
	}
	m.refreshRoots()
	return m
}

func (m *docrootExecMonitor) currentCfg() *config.Config {
	if cfg := config.Active(); cfg != nil {
		return cfg
	}
	return m.cfg
}

func (m *docrootExecMonitor) refreshRoots() {
	m.roots.Store(checks.NewDocrootIndex(checks.ResolveWebRoots(m.currentCfg())))
}

// observe runs on the exec event loop and does no I/O. Even an absolute
// start name can be an alias into a document root; only /proc can resolve it.
func (m *docrootExecMonitor) observe(ev ExecEvent) {
	if ev.UID == 0 {
		return
	}
	m.queue.TrySend(ev)
}

// queueStatuses publishes the inspection queue beside the exec reader's rows.
func (m *docrootExecMonitor) queueStatuses(now time.Time) map[string]queuehealth.Status {
	return map[string]queuehealth.Status{"docroot": m.queue.Snapshot(now)}
}

// run inspects queued starts until ctx ends. attach adds process context to a
// finding before it is published.
func (m *docrootExecMonitor) run(ctx context.Context, attach func(*alert.Finding, ExecEvent)) {
	refresh := time.NewTicker(docrootExecRefreshInterval)
	defer refresh.Stop()
	for {
		if ctx.Err() != nil {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-refresh.C:
			m.refreshRoots()
		case work := <-m.queue.Items():
			if ctx.Err() != nil {
				work.Ticket.Reject(time.Now())
				return
			}
			work.Process(func(ev ExecEvent) {
				f := inspectDocrootExec(m.currentCfg(), int(ev.PID), int(ev.UID), ev.Filename, ev.ParentComm, m.roots.Load())
				if f == nil {
					return
				}
				if ctx.Err() != nil {
					m.queue.Lose(1)
					return
				}
				attach(f, ev)
				if !alert.TryEnqueue(m.alertCh, *f) {
					csmlog.Warn("docroot exec: alert channel full, dropping finding")
				}
			})
		}
	}
}

// start runs the inspection worker until the returned stop is called. The
// caller stops calling observe before it calls stop; stop then waits for the
// worker, closes the queue and discards the starts still waiting in it.
func (m *docrootExecMonitor) start(ctx context.Context, attach func(*alert.Finding, ExecEvent)) (stop func()) {
	ctx, cancel := context.WithCancel(ctx)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		m.run(ctx, attach)
	}()
	return func() {
		cancel()
		wg.Wait()
		m.queue.Close()
		m.queue.DiscardPending()
	}
}
