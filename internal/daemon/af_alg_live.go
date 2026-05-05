package daemon

import (
	"context"
	"strings"
	"sync"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/bpf"
	"github.com/pidginhost/csm/internal/config"
	csmlog "github.com/pidginhost/csm/internal/log"
	"github.com/pidginhost/csm/internal/metrics"
)

// AFAlgLiveMonitor was the local name for the live-monitor interface;
// it is now an alias of the shared bpf.Backend. Existing call sites in
// reactToAFAlgEvent etc. continue to compile.
type AFAlgLiveMonitor = bpf.Backend

// AFAlgBackend* are the operator-facing cfg.Detection.AFAlgBackend values.
// Reuse bpf constants where the public value already matches.
const (
	AFAlgBackendAuto   = bpf.BackendAuto
	AFAlgBackendBPF    = bpf.BackendBPF
	AFAlgBackendAuditd = "auditd"
	AFAlgBackendNone   = bpf.BackendNone
)

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

	switch active {
	case "bpf-lsm":
		bpf.SetActive("af_alg", bpf.BackendBPF)
	case "auditd-tail":
		bpf.SetActive("af_alg", bpf.BackendLegacy)
	default:
		bpf.SetActive("af_alg", bpf.BackendNone)
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
			csmlog.Info("af_alg live monitor: BPF LSM unavailable",
				"state", "bpf-lsm-unsupported",
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
