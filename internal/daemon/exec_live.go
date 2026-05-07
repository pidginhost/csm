package daemon

import (
	"context"
	"errors"
	"strings"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/bpf"
	"github.com/pidginhost/csm/internal/config"
	csmlog "github.com/pidginhost/csm/internal/log"
	"github.com/pidginhost/csm/internal/processctx"
)

// StartExecMonitor selects the active exec-monitor backend based on
// cfg.Detection.ExecMonitorBackend and host capability:
//
//	"auto" (default) -- try BPF, fall back to legacy polling.
//	"bpf"            -- require BPF; return nil if unavailable (no fallback).
//	"legacy"         -- pin legacy polling.
//	"none"           -- disable the live monitor (periodic checks still run).
//
// Unknown values fall back to "auto" with a warning. The metric
// csm_bpf_backend{feature="exec_monitor", kind="..."} reflects the
// chosen path.
func StartExecMonitor(alertCh chan<- alert.Finding, cfg *config.Config) bpf.Backend {
	choice := strings.ToLower(strings.TrimSpace(cfg.Detection.ExecMonitorBackend))
	if choice == "" {
		choice = bpf.BackendAuto
	}
	switch choice {
	case bpf.BackendAuto, bpf.BackendBPF, bpf.BackendLegacy, bpf.BackendNone:
	default:
		csmlog.Warn("exec_monitor: unknown backend choice, using auto", "value", choice)
		choice = bpf.BackendAuto
	}

	if choice == bpf.BackendNone {
		csmlog.Info("exec_monitor: disabled by config")
		bpf.SetActive("exec_monitor", bpf.BackendNone)
		return nil
	}

	if choice == bpf.BackendAuto || choice == bpf.BackendBPF {
		if b, err := tryStartExecBPFFn(context.Background(), alertCh, cfg); err == nil && b != nil {
			csmlog.Info("exec_monitor", "backend", "bpf", "choice", choice)
			bpf.SetActive("exec_monitor", bpf.BackendBPF)
			return b
		} else if err != nil {
			level := "bpf-unsupported"
			if errors.Is(err, bpf.ErrNotBuilt) {
				level = "bpf-not-built"
			}
			csmlog.Info("exec_monitor: BPF unavailable", "state", level, "reason", err.Error(), "choice", choice)
			if choice == bpf.BackendBPF {
				csmlog.Warn("exec_monitor: backend=bpf but BPF unavailable; no live monitor", "reason", err.Error())
				bpf.SetActive("exec_monitor", bpf.BackendNone)
				return nil
			}
		}
	}

	poller := newExecPoller(cfg, alertCh)
	csmlog.Info("exec_monitor", "backend", "legacy", "choice", choice)
	bpf.SetActive("exec_monitor", bpf.BackendLegacy)
	return poller
}

// tryStartExecBPFFn is the package-level indirection so tests can substitute
// a fake without the bpf build tag.
var tryStartExecBPFFn = tryStartExecBPF

func tryStartExecBPF(ctx context.Context, ch chan<- alert.Finding, cfg *config.Config) (bpf.Backend, error) {
	b, err := startExecBPF(ctx, ch, cfg)
	if err != nil {
		return nil, err
	}
	return b, nil
}

// populateProcessCtxFromExec writes the BPF exec event into the process
// context cache without doing identity or /proc work in the event loop. Zero
// PID is ignored (synthetic boot-time noise).
func populateProcessCtxFromExec(cache *processctx.Cache, ev ExecEvent) {
	if ev.PID == 0 {
		return
	}
	cache.PutFromExec(int(ev.PID), int(ev.PPID), int(ev.UID), ev.Comm, ev.Filename)
}

func attachProcessCtxToExecFinding(cache *processctx.Cache, f *alert.Finding, ev ExecEvent) {
	if pc, _ := cache.MaterializeVerified(int(ev.PID), int(ev.UID), true, ev.Comm); pc != nil {
		f.Process = pc
	}
}

func processctxRequestFromExec(ev ExecEvent) processctx.EnrichRequest {
	return processctx.EnrichRequest{PID: int(ev.PID), UID: int(ev.UID), UIDKnown: true, Comm: ev.Comm}
}
