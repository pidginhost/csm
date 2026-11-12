//go:build !linux

package daemon

import (
	"context"
	"errors"
)

// placementFID is the non-Linux placeholder for placement_fid_linux.go.
type placementFID struct{}

func (p *placementFID) Mode() string          { return "legacy" }
func (p *placementFID) EventCount() uint64    { return 0 }
func (p *placementFID) Run(_ context.Context) {}

func startPlacementFID(_ context.Context, _ *FileMonitor) (*placementFID, error) {
	return nil, errors.ErrUnsupported
}
