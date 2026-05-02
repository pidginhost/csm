//go:build !(linux && bpf)

package daemon

import (
	"context"
	"errors"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

// errBPFNotBuilt is returned by tryStartBPFLSM when CSM was built without
// the `bpf` build tag. The coordinator handles this identically to a kernel
// that lacks BPF LSM support: log it and fall back to the audit listener.
var errBPFNotBuilt = errors.New("BPF LSM support not compiled in (rebuild with -tags bpf)")

// tryStartBPFLSM is the no-tag fallback. The real implementation lives in
// af_alg_bpf.go behind //go:build linux && bpf.
func tryStartBPFLSM(_ context.Context, _ chan<- alert.Finding, _ *config.Config) (AFAlgLiveMonitor, error) {
	return nil, errBPFNotBuilt
}
