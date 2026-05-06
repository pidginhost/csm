//go:build !(linux && bpf)

package daemon

import (
	"context"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/bpf"
	"github.com/pidginhost/csm/internal/config"
)

// connectionBPF is the no-tag placeholder for the BPF cgroup/connect backend.
// The real type with map handles, links, and the ringbuf reader lives in
// connection_bpf.go behind //go:build linux && bpf. On any other build, the
// coordinator never reaches this stub: startConnectionBPF returns
// bpf.ErrNotBuilt before a value is constructed.
type connectionBPF struct{}

func (c *connectionBPF) Mode() string          { return "bpf" }
func (c *connectionBPF) EventCount() uint64    { return 0 }
func (c *connectionBPF) Run(_ context.Context) {}

func startConnectionBPF(_ context.Context, _ chan<- alert.Finding, _ *config.Config) (*connectionBPF, error) {
	return nil, bpf.ErrNotBuilt
}
