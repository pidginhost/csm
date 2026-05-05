package daemon

import (
	"context"
	"sync/atomic"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/config"
	csmlog "github.com/pidginhost/csm/internal/log"
)

// connectionPoller is the userspace fallback. It runs CheckOutboundUserConnections
// on a fixed interval and forwards any findings to the alert channel. Used
// when the BPF backend is unavailable (no bpf tag, kernel rejects program,
// or operator pinned legacy via Detection.ConnectionTrackerBackend).
type connectionPoller struct {
	cfg     *config.Config
	alertCh chan<- alert.Finding
	count   atomic.Uint64
}

func newConnectionPoller(cfg *config.Config, alertCh chan<- alert.Finding) *connectionPoller {
	return &connectionPoller{cfg: cfg, alertCh: alertCh}
}

func (p *connectionPoller) Mode() string       { return "legacy" }
func (p *connectionPoller) EventCount() uint64 { return p.count.Load() }

func (p *connectionPoller) Run(ctx context.Context) {
	interval := pollerInterval(p.cfg)
	t := time.NewTicker(interval)
	defer t.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			findings := checks.CheckOutboundUserConnections(ctx, p.cfg, nil)
			for _, f := range findings {
				p.count.Add(1)
				select {
				case p.alertCh <- f:
				default:
					csmlog.Warn("connection legacy: alert channel full, dropping finding")
				}
			}
		}
	}
}

// pollerInterval returns the configured polling interval, falling back to a
// 30-second default. Task 8 will add Detection.ConnectionPollInterval; until
// then the function returns the literal default and reads no config field.
func pollerInterval(_ *config.Config) time.Duration {
	// TODO Task 8: read from cfg.Detection.ConnectionPollInterval.
	return 30 * time.Second
}
