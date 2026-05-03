package daemon

import (
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/health"
	"github.com/pidginhost/csm/internal/integrity"
	"github.com/pidginhost/csm/internal/store"
)

// Hostname implements health.Provider.
func (d *Daemon) Hostname() string {
	cfg := d.currentCfg()
	if cfg == nil {
		return ""
	}
	return cfg.Hostname
}

// StartedAt implements health.Provider.
func (d *Daemon) StartedAt() time.Time {
	return d.startTime
}

// LatestScan implements health.Provider.
func (d *Daemon) LatestScan() time.Time {
	if d.store == nil {
		return time.Time{}
	}
	return d.store.LatestScanTime()
}

// BaselineAt implements health.Provider.
// TODO: track baseline timestamp distinctly in state.Store so this can return the real time.
func (d *Daemon) BaselineAt() time.Time {
	return time.Time{}
}

// StoreHealthy implements health.Provider.
func (d *Daemon) StoreHealthy() bool {
	s := store.Global()
	if s == nil {
		return false
	}
	return s.IsHealthy()
}

// StoreSizeMB implements health.Provider.
func (d *Daemon) StoreSizeMB() float64 {
	s := store.Global()
	if s == nil {
		return 0
	}
	return float64(s.SizeBytes()) / (1024 * 1024)
}

// SeverityCounts implements health.Provider.
// Buckets the latest findings by severity name.
func (d *Daemon) SeverityCounts() map[string]int {
	out := map[string]int{"critical": 0, "high": 0, "warning": 0}
	if d.store == nil {
		return out
	}
	for _, f := range d.store.LatestFindings() {
		switch f.Severity {
		case alert.Critical:
			out["critical"]++
		case alert.High:
			out["high"]++
		default:
			out["warning"]++
		}
	}
	return out
}

// BlocklistSize implements health.Provider.
func (d *Daemon) BlocklistSize() int {
	s := store.Global()
	if s == nil {
		return 0
	}
	return len(s.LoadFirewallState().Blocked)
}

// HistoryCount implements health.Provider.
func (d *Daemon) HistoryCount() int {
	s := store.Global()
	if s == nil {
		return 0
	}
	return s.HistoryCount()
}

// ConfigHash implements health.Provider.
func (d *Daemon) ConfigHash() string {
	cfg := d.currentCfg()
	if cfg == nil {
		return ""
	}
	return cfg.Integrity.ConfigHash
}

// BinaryHash implements health.Provider.
// Computes the hash on first call via the known binary path; returns empty on error.
func (d *Daemon) BinaryHash() string {
	if d.binaryPath == "" {
		return ""
	}
	h, err := integrity.HashFile(d.binaryPath)
	if err != nil {
		return ""
	}
	return h
}

// compile-time check: Daemon satisfies health.Provider.
var _ health.Provider = (*Daemon)(nil)
