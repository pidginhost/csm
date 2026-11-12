package daemon

import (
	"errors"
	"strings"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/bpf"
	csmlog "github.com/pidginhost/csm/internal/log"
)

// startLiveBackend selects the backend for one live monitor from the
// operator's choice and host capability:
//
//	"auto" (default) -- try BPF, fall back to legacy polling, else none.
//	"bpf"            -- require BPF; return nil if unavailable (no fallback).
//	"legacy"         -- pin legacy polling.
//	"none"           -- disable the live monitor (the periodic check still runs).
//
// Unknown values fall back to "auto" with a warning. The metric
// csm_bpf_backend{feature=<feature>, kind="..."} reflects the chosen path.
func startLiveBackend(feature, configured string, alertCh chan<- alert.Finding,
	tryBPF func() (bpf.Backend, error), legacy func() bpf.Backend) bpf.Backend {
	choice := strings.ToLower(strings.TrimSpace(configured))
	if choice == "" {
		choice = bpf.BackendAuto
	}
	switch choice {
	case bpf.BackendAuto, bpf.BackendBPF, bpf.BackendLegacy, bpf.BackendNone:
	default:
		csmlog.Warn(feature+": unknown backend choice, using auto", "value", choice)
		choice = bpf.BackendAuto
	}

	if choice == bpf.BackendNone {
		csmlog.Info(feature + ": disabled by config")
		bpf.SetActive(feature, bpf.BackendNone)
		return nil
	}

	var bpfErr error
	if choice == bpf.BackendAuto || choice == bpf.BackendBPF {
		if b, err := tryBPF(); err == nil && b != nil {
			csmlog.Info(feature, "backend", "bpf", "choice", choice)
			bpf.SetActive(feature, bpf.BackendBPF)
			return b
		} else if err != nil {
			bpfErr = err
			level := "bpf-unsupported"
			if errors.Is(err, bpf.ErrNotBuilt) {
				level = "bpf-not-built"
			}
			csmlog.Info(feature+": BPF unavailable", "state", level, "reason", err.Error(), "choice", choice)
			if choice == bpf.BackendBPF {
				csmlog.Warn(feature+": backend=bpf but BPF unavailable; no live monitor", "reason", err.Error())
				bpf.SetActive(feature, bpf.BackendNone)
				emitBPFUnavailableFinding(alertCh, feature, choice, "", err)
				return nil
			}
		}
	}

	poller := legacy()
	if poller == nil {
		// Only a legacy backend that probes the kernel can fail to start.
		// Its caller knows why, so it decides whether that is a finding.
		csmlog.Info(feature+": no legacy backend available", "choice", choice)
		bpf.SetActive(feature, bpf.BackendNone)
		return nil
	}
	csmlog.Info(feature, "backend", "legacy", "choice", choice)
	bpf.SetActive(feature, bpf.BackendLegacy)
	if bpfErr != nil {
		emitBPFUnavailableFinding(alertCh, feature, choice, bpf.BackendLegacy, bpfErr)
	}
	return poller
}
