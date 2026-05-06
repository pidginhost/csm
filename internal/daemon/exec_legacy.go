package daemon

import (
	"context"
	"sync/atomic"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/config"
	csmlog "github.com/pidginhost/csm/internal/log"
	"github.com/pidginhost/csm/internal/state"
)

// execPoller wraps the periodic CheckSuspiciousProcesses + CheckFakeKernelThreads
// in a goroutine. Used when the BPF backend is unavailable or operator-disabled.
// Detection latency for already-running processes equals the poll interval (default
// 30 minutes, matching the existing deep-tier cadence).
type execPoller struct {
	cfg     *config.Config
	alertCh chan<- alert.Finding
	count   atomic.Uint64
}

func newExecPoller(cfg *config.Config, alertCh chan<- alert.Finding) *execPoller {
	return &execPoller{cfg: cfg, alertCh: alertCh}
}

func (p *execPoller) Mode() string       { return "legacy" }
func (p *execPoller) EventCount() uint64 { return p.count.Load() }

func (p *execPoller) Run(ctx context.Context) {
	interval := execPollerInterval(p.cfg)
	t := time.NewTicker(interval)
	defer t.Stop()

	emit := func(fs []alert.Finding) {
		for _, f := range fs {
			p.count.Add(1)
			select {
			case p.alertCh <- f:
			default:
				csmlog.Warn("exec legacy: alert channel full, dropping finding")
			}
		}
	}

	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			emit(checks.CheckSuspiciousProcesses(ctx, p.cfg, (*state.Store)(nil)))
			emit(checks.CheckFakeKernelThreads(ctx, p.cfg, (*state.Store)(nil)))
		}
	}
}

func execPollerInterval(cfg *config.Config) time.Duration {
	if d := cfg.Detection.ExecMonitorPollInterval; d > 0 {
		return d
	}
	return 30 * time.Minute
}
