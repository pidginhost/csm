package daemon

import (
	"context"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/bpf"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/state"
)

// StartSensitiveFileMonitor starts the live sensitive-file write monitor chosen by
// detection.sensitive_files_backend; see startLiveBackend for the choices.
func StartSensitiveFileMonitor(alertCh chan<- alert.Finding, cfg *config.Config, store *state.Store) bpf.Backend {
	return startLiveBackend("sensitive_files", cfg.Detection.SensitiveFilesBackend, alertCh,
		func() (bpf.Backend, error) { return tryStartSensitiveFileBPFFn(context.Background(), alertCh, cfg) },
		func() bpf.Backend { return newSensitiveFilePoller(cfg, store, alertCh) })
}

var tryStartSensitiveFileBPFFn = tryStartSensitiveFileBPF

func tryStartSensitiveFileBPF(ctx context.Context, ch chan<- alert.Finding, cfg *config.Config) (bpf.Backend, error) {
	b, err := startSensitiveFileBPF(ctx, ch, cfg)
	if err != nil {
		return nil, err
	}
	return b, nil
}
