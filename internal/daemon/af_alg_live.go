package daemon

import (
	"context"
	"errors"
	"strings"
	"sync"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	csmlog "github.com/pidginhost/csm/internal/log"
	"github.com/pidginhost/csm/internal/metrics"
)

// AFAlgLiveMonitor is the common shape for the two Copy-Fail (CVE-2026-31431)
// live-detection backends: a BPF LSM hook that blocks the AF_ALG socket call
// in the kernel itself, and the audit-log inotify listener that reacts after
// auditd has logged the syscall. Both feed the same alert.Finding channel and
// share af_alg_react.go for kill/quarantine, so the daemon doesn't care which
// backend is running.
type AFAlgLiveMonitor interface {
	Mode() string
	EventCount() uint64
	Run(ctx context.Context)
}

// AFAlgBackendKind enumerates the possible operator settings for
// Detection.AFAlgBackend. Validated at coordinator startup; unknown
// values fall back to "auto" with a warning.
const (
	AFAlgBackendAuto   = "auto"
	AFAlgBackendBPF    = "bpf"
	AFAlgBackendAuditd = "auditd"
	AFAlgBackendNone   = "none"
)

// errBPFPhaseBPending fires when the kernel can run BPF LSM programs but
// the blocking program + perf consumer (Phase B in the plan) hasn't
// shipped yet. The coordinator treats this as "BPF unavailable" so the
// audit listener takes over, but logs it as a distinct state so operators
// can see the kernel is ready when a Phase-B build does land. Defined
// here (not behind the bpf tag) so the coordinator can errors.Is against
// it on every build, including tests that fake the probe.
var errBPFPhaseBPending = errors.New("BPF LSM kernel support detected but blocking program not yet implemented")

var (
	afAlgBackendMetricOnce sync.Once
	afAlgBackendMetric     *metrics.GaugeVec
)

func ensureAFAlgBackendMetric() {
	afAlgBackendMetricOnce.Do(func() {
		afAlgBackendMetric = metrics.NewGaugeVec(
			"csm_af_alg_backend",
			"Active AF_ALG (Copy Fail) live-monitor backend; 1 for the selected kind, 0 otherwise.",
			[]string{"kind"},
		)
		metrics.MustRegister("csm_af_alg_backend", afAlgBackendMetric)
	})
}

func setAFAlgBackendMetric(active string) {
	ensureAFAlgBackendMetric()
	for _, k := range []string{"bpf-lsm", "auditd-tail", "none"} {
		v := 0.0
		if k == active {
			v = 1.0
		}
		afAlgBackendMetric.With(k).Set(v)
	}
}

// StartAFAlgLiveMonitor returns the live monitor selected by
// cfg.Detection.AFAlgBackend. "" / "auto" tries BPF LSM first (when
// compiled in and kernel-supported) and falls back to the audit listener.
// "bpf" requires BPF — no audit fallback if BPF is unavailable, useful for
// hosts where the operator deliberately wants the kernel-side block or
// nothing. "auditd" pins the audit listener even on BPF-capable hosts, the
// kill switch when a BPF-tagged release misbehaves. "none" disables the
// live monitor (the periodic critical-tier check still runs). Returns nil
// when no backend ends up active; the metric csm_af_alg_backend{kind=...}
// reflects whichever path was selected.
func StartAFAlgLiveMonitor(alertCh chan<- alert.Finding, cfg *config.Config) AFAlgLiveMonitor {
	choice := strings.ToLower(strings.TrimSpace(cfg.Detection.AFAlgBackend))
	if choice == "" {
		choice = AFAlgBackendAuto
	}
	switch choice {
	case AFAlgBackendAuto, AFAlgBackendBPF, AFAlgBackendAuditd, AFAlgBackendNone:
	default:
		csmlog.Warn("af_alg live monitor: unknown backend choice, falling back to auto",
			"value", choice,
		)
		choice = AFAlgBackendAuto
	}

	if choice == AFAlgBackendNone {
		csmlog.Info("af_alg live monitor: disabled by config")
		setAFAlgBackendMetric("none")
		return nil
	}

	if choice == AFAlgBackendAuto || choice == AFAlgBackendBPF {
		if mon, err := tryStartBPFLSMFn(context.Background(), alertCh, cfg); err == nil && mon != nil {
			csmlog.Info("af_alg live monitor", "backend", "bpf-lsm", "choice", choice)
			setAFAlgBackendMetric("bpf-lsm")
			return mon
		} else if err != nil {
			level := "bpf-lsm-unsupported"
			if errors.Is(err, errBPFPhaseBPending) {
				// Phase-A-only build on a BPF-capable kernel: distinct
				// from "kernel can't run BPF LSM" so operators can tell
				// "deploy a -tags bpf build to enable" from "kernel
				// rebuild required".
				level = "bpf-lsm-pending"
			}
			csmlog.Info("af_alg live monitor: BPF LSM unavailable",
				"state", level,
				"reason", err.Error(),
				"choice", choice,
			)
			if choice == AFAlgBackendBPF {
				csmlog.Warn("af_alg live monitor: af_alg_backend=bpf but BPF unavailable; no live detection",
					"reason", err.Error(),
				)
				setAFAlgBackendMetric("none")
				return nil
			}
		}
	}

	listener, err := NewAFAlgAuditListener(alertCh, cfg)
	if err != nil {
		csmlog.Warn("af_alg live monitor: auditd fallback unavailable", "err", err)
		setAFAlgBackendMetric("none")
		return nil
	}
	csmlog.Info("af_alg live monitor", "backend", "auditd-tail", "choice", choice)
	setAFAlgBackendMetric("auditd-tail")
	return listener
}

// tryStartBPFLSMFn is a package-level indirection so tests can substitute a
// fake for the BPF probe path without needing the bpf build tag or kernel
// privileges. Production code goes through tryStartBPFLSM, which is the
// stub on default builds and the real probe on -tags bpf builds.
var tryStartBPFLSMFn = tryStartBPFLSM
