//go:build !(linux && bpf)

package daemon

import (
	"context"

	"github.com/pidginhost/csm/internal/bpf"
)

// placementBPF is the no-tag placeholder for the BPF placement monitor in
// placement_bpf.go.
type placementBPF struct{}

func (p *placementBPF) Mode() string          { return "bpf" }
func (p *placementBPF) EventCount() uint64    { return 0 }
func (p *placementBPF) Run(_ context.Context) {}

func startPlacementBPF(_ context.Context, _ *FileMonitor) (*placementBPF, error) {
	return nil, bpf.ErrNotBuilt
}
