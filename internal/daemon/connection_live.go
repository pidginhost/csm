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

// StartConnectionTracker selects the active connection-tracker backend based
// on cfg.Detection.ConnectionTrackerBackend and host capability:
//
//	"auto" (default) -- try BPF, fall back to legacy polling.
//	"bpf"            -- require BPF; return nil if unavailable (no fallback).
//	"legacy"         -- pin legacy polling.
//	"none"           -- disable the live tracker (the periodic check still runs).
//
// Unknown values fall back to "auto" with a warning. The metric
// csm_bpf_backend{feature="connection_tracker", kind="..."} reflects the
// chosen path.
func StartConnectionTracker(alertCh chan<- alert.Finding, cfg *config.Config) bpf.Backend {
	choice := strings.ToLower(strings.TrimSpace(cfg.Detection.ConnectionTrackerBackend))
	if choice == "" {
		choice = bpf.BackendAuto
	}
	switch choice {
	case bpf.BackendAuto, bpf.BackendBPF, bpf.BackendLegacy, bpf.BackendNone:
	default:
		csmlog.Warn("connection_tracker: unknown backend choice, using auto", "value", choice)
		choice = bpf.BackendAuto
	}

	if choice == bpf.BackendNone {
		csmlog.Info("connection_tracker: disabled by config")
		bpf.SetActive("connection_tracker", bpf.BackendNone)
		return nil
	}

	if choice == bpf.BackendAuto || choice == bpf.BackendBPF {
		if b, err := tryStartConnectionBPFFn(context.Background(), alertCh, cfg); err == nil && b != nil {
			csmlog.Info("connection_tracker", "backend", "bpf", "choice", choice)
			bpf.SetActive("connection_tracker", bpf.BackendBPF)
			return b
		} else if err != nil {
			level := "bpf-unsupported"
			if errors.Is(err, bpf.ErrNotBuilt) {
				level = "bpf-not-built"
			}
			csmlog.Info("connection_tracker: BPF unavailable", "state", level, "reason", err.Error(), "choice", choice)
			if choice == bpf.BackendBPF {
				csmlog.Warn("connection_tracker: backend=bpf but BPF unavailable; no live tracker", "reason", err.Error())
				bpf.SetActive("connection_tracker", bpf.BackendNone)
				return nil
			}
		}
	}

	poller := newConnectionPoller(cfg, alertCh)
	csmlog.Info("connection_tracker", "backend", "legacy", "choice", choice)
	bpf.SetActive("connection_tracker", bpf.BackendLegacy)
	return poller
}

// tryStartConnectionBPFFn is the package-level indirection so tests can
// substitute a fake without the bpf build tag.
var tryStartConnectionBPFFn = tryStartConnectionBPF

func tryStartConnectionBPF(ctx context.Context, ch chan<- alert.Finding, cfg *config.Config) (bpf.Backend, error) {
	b, err := startConnectionBPF(ctx, ch, cfg)
	if err != nil {
		return nil, err
	}
	return b, nil
}

// attachProcessCtxToFinding sets f.Process from the cache when present, or
// enqueues a /proc enrichment so the next finding for the same PID benefits.
// Cache miss is the common case for short-lived processes; the finding is
// emitted with whatever context already exists (often none).
func attachProcessCtxToFinding(cache *processctx.Cache, enr *processctx.Enricher, f *alert.Finding, ev ConnectionEvent) {
	if pc := cache.Materialize(int(ev.PID)); pc != nil {
		f.Process = pc
		return
	}
	enr.Enqueue(processctx.EnrichRequest{PID: int(ev.PID), UID: int(ev.UID), Comm: ev.Comm})
}
