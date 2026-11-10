package daemon

import (
	"context"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/bpf"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/processctx"
)

// StartExecMonitor starts the live exec monitor chosen by
// detection.exec_monitor_backend; see startLiveBackend for the choices.
func StartExecMonitor(alertCh chan<- alert.Finding, cfg *config.Config) bpf.Backend {
	return startLiveBackend("exec_monitor", cfg.Detection.ExecMonitorBackend, alertCh,
		func() (bpf.Backend, error) { return tryStartExecBPFFn(context.Background(), alertCh, cfg) },
		func() bpf.Backend { return newExecPoller(cfg, alertCh) })
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
// context cache without doing identity work in the event loop. Zero PID is
// ignored (synthetic boot-time noise).
func populateProcessCtxFromExec(cache *processctx.Cache, ev ExecEvent, startedAt time.Time) {
	if ev.PID == 0 {
		return
	}
	cache.PutFromExecStartedAt(int(ev.PID), int(ev.PPID), int(ev.UID), ev.Comm, ev.Filename, startedAt)
}

func attachProcessCtxToExecFinding(cache *processctx.Cache, f *alert.Finding, ev ExecEvent) {
	req := processctx.EnrichRequest{
		PID:       int(ev.PID),
		UID:       int(ev.UID),
		UIDKnown:  true,
		Comm:      ev.Comm,
		StartedAt: processCtxStartedAt(int(ev.PID)),
	}
	if pc, _ := cache.MaterializeVerifiedSnapshot(req); pc != nil {
		f.Process = pc
	}
}

// processctxRequestFromExec builds the EnrichRequest snapshot used by the BPF
// exec consumer. Lives here (no build tag) so unit tests on darwin can verify
// the field mapping without a Linux+bpf build.
func processctxRequestFromExec(ev ExecEvent) processctx.EnrichRequest {
	pid := int(ev.PID)
	return processctx.EnrichRequest{
		PID:       pid,
		UID:       int(ev.UID),
		UIDKnown:  true,
		Comm:      ev.Comm,
		StartedAt: processCtxStartedAt(pid),
	}
}
