//go:build !(linux && bpf)

package daemon

import (
	"context"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/bpf"
	"github.com/pidginhost/csm/internal/config"
)

// execBPF is the no-tag placeholder for the BPF exec-monitor backend. The
// real type with a tracepoint link and ringbuf reader lives in exec_bpf.go
// behind //go:build linux && bpf.
type execBPF struct{}

func (e *execBPF) Mode() string          { return "bpf" }
func (e *execBPF) EventCount() uint64    { return 0 }
func (e *execBPF) Run(_ context.Context) {}

func startExecBPF(_ context.Context, _ chan<- alert.Finding, _ *config.Config) (*execBPF, error) {
	return nil, bpf.ErrNotBuilt
}
