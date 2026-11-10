package daemon

import (
	"context"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/bpf"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/processctx"
)

// StartConnectionTracker starts the live connection tracker chosen by
// detection.connection_tracker_backend; see startLiveBackend for the choices.
func StartConnectionTracker(alertCh chan<- alert.Finding, cfg *config.Config) bpf.Backend {
	return startLiveBackend("connection_tracker", cfg.Detection.ConnectionTrackerBackend, alertCh,
		func() (bpf.Backend, error) { return tryStartConnectionBPFFn(context.Background(), alertCh, cfg) },
		func() bpf.Backend { return newConnectionPoller(cfg, alertCh) })
}

func activeConnectionCfg(startup *config.Config) *config.Config {
	if cfg := config.Active(); cfg != nil {
		return cfg
	}
	return startup
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
	if ev.PID == 0 {
		return
	}
	req := processctxRequestFromConnection(ev)
	if pc, needsEnrichment := cache.MaterializeVerifiedSnapshot(req); pc != nil {
		f.Process = pc
		if pc.Account != "" && (f.Check == "direct_smtp_egress" || f.TenantID == "") {
			f.TenantID = pc.Account
		}
		if needsEnrichment {
			enr.Enqueue(req)
		}
		return
	}
	enr.Enqueue(req)
}

func processctxRequestFromConnection(ev ConnectionEvent) processctx.EnrichRequest {
	pid := int(ev.PID)
	return processctx.EnrichRequest{
		PID:       pid,
		UID:       int(ev.UID),
		UIDKnown:  true,
		Comm:      ev.Comm,
		StartedAt: processCtxStartedAt(pid),
	}
}
