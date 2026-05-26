package daemon

import (
	"context"
	"errors"
	"strings"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/bpf"
	"github.com/pidginhost/csm/internal/config"
	csmlog "github.com/pidginhost/csm/internal/log"
	"github.com/pidginhost/csm/internal/state"
)

// StartSensitiveFileMonitor selects the active sensitive-file write monitor
// based on cfg.Detection.SensitiveFilesBackend and host capability.
//
//	"auto" (default) -- try BPF, fall back to legacy hash-comparison polling.
//	"bpf"            -- require BPF; return nil if unavailable (no fallback).
//	"legacy"         -- pin legacy polling.
//	"none"           -- disable the live monitor (the periodic check still runs).
//
// Unknown values fall back to "auto" with a warning. The metric
// csm_bpf_backend{feature="sensitive_files", kind="..."} reflects the
// chosen path.
func StartSensitiveFileMonitor(alertCh chan<- alert.Finding, cfg *config.Config, store *state.Store) bpf.Backend {
	choice := strings.ToLower(strings.TrimSpace(cfg.Detection.SensitiveFilesBackend))
	if choice == "" {
		choice = bpf.BackendAuto
	}
	switch choice {
	case bpf.BackendAuto, bpf.BackendBPF, bpf.BackendLegacy, bpf.BackendNone:
	default:
		csmlog.Warn("sensitive_files: unknown backend choice, using auto", "value", choice)
		choice = bpf.BackendAuto
	}

	if choice == bpf.BackendNone {
		csmlog.Info("sensitive_files: disabled by config")
		bpf.SetActive("sensitive_files", bpf.BackendNone)
		return nil
	}

	var bpfErr error
	if choice == bpf.BackendAuto || choice == bpf.BackendBPF {
		if b, err := tryStartSensitiveFileBPFFn(context.Background(), alertCh, cfg); err == nil && b != nil {
			csmlog.Info("sensitive_files", "backend", "bpf", "choice", choice)
			bpf.SetActive("sensitive_files", bpf.BackendBPF)
			return b
		} else if err != nil {
			bpfErr = err
			level := "bpf-unsupported"
			if errors.Is(err, bpf.ErrNotBuilt) {
				level = "bpf-not-built"
			}
			csmlog.Info("sensitive_files: BPF unavailable", "state", level, "reason", err.Error(), "choice", choice)
			if choice == bpf.BackendBPF {
				csmlog.Warn("sensitive_files: backend=bpf but BPF unavailable; no live monitor", "reason", err.Error())
				bpf.SetActive("sensitive_files", bpf.BackendNone)
				emitBPFUnavailableFinding(alertCh, "sensitive_files", choice, "", err)
				return nil
			}
		}
	}

	poller := newSensitiveFilePoller(cfg, store, alertCh)
	csmlog.Info("sensitive_files", "backend", "legacy", "choice", choice)
	bpf.SetActive("sensitive_files", bpf.BackendLegacy)
	if bpfErr != nil {
		emitBPFUnavailableFinding(alertCh, "sensitive_files", choice, bpf.BackendLegacy, bpfErr)
	}
	return poller
}

var tryStartSensitiveFileBPFFn = tryStartSensitiveFileBPF

func tryStartSensitiveFileBPF(ctx context.Context, ch chan<- alert.Finding, cfg *config.Config) (bpf.Backend, error) {
	b, err := startSensitiveFileBPF(ctx, ch, cfg)
	if err != nil {
		return nil, err
	}
	return b, nil
}
