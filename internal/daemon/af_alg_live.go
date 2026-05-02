//go:build linux

package daemon

import (
	"context"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	csmlog "github.com/pidginhost/csm/internal/log"
)

// AFAlgLiveMonitor is the common shape for the two Copy-Fail (CVE-2026-31431)
// live-detection backends: a BPF LSM hook that blocks the AF_ALG socket call
// in the kernel itself, and the audit-log inotify listener that reacts after
// auditd has logged the syscall. Both feed the same alert.Finding channel and
// share af_alg_react.go for kill/quarantine, so the daemon doesn't care which
// backend is running.
type AFAlgLiveMonitor interface {
	Mode() string
	Run(ctx context.Context)
}

// StartAFAlgLiveMonitor returns the best-available live monitor for this
// host. It prefers BPF LSM (compiled in via -tags bpf and supported by the
// running kernel) because it stops the syscall in-kernel before any user-
// space damage; otherwise it falls back to the audit-log listener, which any
// kernel with auditd can run. Returns nil only when neither backend is
// usable — in that case the periodic critical-tier check still scans for
// retroactive AF_ALG usage, so detection is degraded but not absent.
func StartAFAlgLiveMonitor(alertCh chan<- alert.Finding, cfg *config.Config) AFAlgLiveMonitor {
	if mon, err := tryStartBPFLSM(context.Background(), alertCh, cfg); err == nil && mon != nil {
		csmlog.Info("af_alg live monitor", "backend", "bpf-lsm")
		return mon
	} else if err != nil {
		csmlog.Info("af_alg live monitor: BPF LSM unavailable", "reason", err.Error())
	}

	listener, err := NewAFAlgAuditListener(alertCh, cfg)
	if err != nil {
		csmlog.Warn("af_alg live monitor: auditd fallback unavailable", "err", err)
		return nil
	}
	csmlog.Info("af_alg live monitor", "backend", "auditd-tail")
	return listener
}
