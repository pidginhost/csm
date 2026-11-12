//go:build !(linux && bpf)

package daemon

import (
	"context"
	"errors"
	"testing"

	"github.com/pidginhost/csm/internal/bpf"
)

func TestStartPlacementBPFWithoutTheBuildTag(t *testing.T) {
	var backend bpf.Backend
	p, err := startPlacementBPF(context.Background(), nil)
	if !errors.Is(err, bpf.ErrNotBuilt) || p != nil {
		t.Fatalf("startPlacementBPF = %v, %v; want nil, ErrNotBuilt", p, err)
	}
	backend = p
	_ = backend
}
