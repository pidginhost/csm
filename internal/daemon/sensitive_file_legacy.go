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

// sensitiveFilePoller wraps checks.CheckSensitiveFiles in a goroutine.
// Used when the BPF backend is unavailable or operator-disabled. Detection
// latency equals the poll interval (default 5 minutes).
type sensitiveFilePoller struct {
	cfg     *config.Config
	store   *state.Store
	alertCh chan<- alert.Finding
	count   atomic.Uint64
}

func newSensitiveFilePoller(cfg *config.Config, store *state.Store, alertCh chan<- alert.Finding) *sensitiveFilePoller {
	return &sensitiveFilePoller{cfg: cfg, store: store, alertCh: alertCh}
}

func (p *sensitiveFilePoller) Mode() string       { return "legacy" }
func (p *sensitiveFilePoller) EventCount() uint64 { return p.count.Load() }

func (p *sensitiveFilePoller) Run(ctx context.Context) {
	interval := sensitiveFilePollerInterval(p.cfg)
	t := time.NewTicker(interval)
	defer t.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			for _, f := range checks.CheckSensitiveFiles(ctx, p.cfg, p.store) {
				p.count.Add(1)
				select {
				case p.alertCh <- f:
				default:
					csmlog.Warn("sensitive_file legacy: alert channel full, dropping finding")
				}
			}
		}
	}
}

func sensitiveFilePollerInterval(cfg *config.Config) time.Duration {
	if d := cfg.Detection.SensitiveFilesPollInterval; d > 0 {
		return d
	}
	return 5 * time.Minute
}
