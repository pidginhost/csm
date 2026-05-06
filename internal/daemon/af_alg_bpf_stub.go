//go:build !(linux && bpf)

package daemon

import (
	"context"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/bpf"
	"github.com/pidginhost/csm/internal/config"
)

// tryStartBPFLSM is the no-tag fallback. The real implementation lives in
// af_alg_bpf.go behind //go:build linux && bpf.
func tryStartBPFLSM(_ context.Context, _ chan<- alert.Finding, _ *config.Config) (AFAlgLiveMonitor, error) {
	return nil, bpf.ErrNotBuilt
}
