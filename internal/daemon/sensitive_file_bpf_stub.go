//go:build !(linux && bpf)

package daemon

import (
	"context"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/bpf"
	"github.com/pidginhost/csm/internal/config"
)

// sensitiveFileBPF is the no-tag placeholder for the BPF sensitive-file
// monitor. The real type with BPF map handles, link, and the ringbuf reader
// lives in sensitive_file_bpf.go behind //go:build linux && bpf.
type sensitiveFileBPF struct{}

func (s *sensitiveFileBPF) Mode() string          { return "bpf" }
func (s *sensitiveFileBPF) EventCount() uint64    { return 0 }
func (s *sensitiveFileBPF) Run(_ context.Context) {}

func startSensitiveFileBPF(_ context.Context, _ chan<- alert.Finding, _ *config.Config) (*sensitiveFileBPF, error) {
	return nil, bpf.ErrNotBuilt
}
