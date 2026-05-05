//go:build linux && bpf

package daemon

import (
	"context"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/bpf"
	"github.com/pidginhost/csm/internal/config"
)

// tryStartBPFLSM is the bpf-tag implementation. It checks the kernel for
// BPF LSM support via the shared probe; if unavailable it returns
// bpf.ErrUnsupported, otherwise it returns errBPFPhaseBPending so the
// coordinator continues to use the audit-log listener until Phase B's
// blocking program lands.
func tryStartBPFLSM(_ context.Context, _ chan<- alert.Finding, _ *config.Config) (AFAlgLiveMonitor, error) {
	if !bpf.Probe().LSMAttach {
		return nil, bpf.ErrUnsupported
	}
	return nil, errBPFPhaseBPending
}
