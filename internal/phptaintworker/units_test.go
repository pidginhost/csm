package phptaintworker

import (
	"slices"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/phptaintipc"
)

func TestUnitConfig(t *testing.T) {
	cfg := UnitConfig("/opt/csm/csm", "csm-phptaint-worker", nil)
	if cfg.Command != "/opt/csm/csm" || cfg.Prefix != "csm-phptaint-worker" {
		t.Fatalf("command %q prefix %q", cfg.Command, cfg.Prefix)
	}
	if !slices.Equal(cfg.Args, []string{"phptaint-worker", "--memory-limit=536870912"}) {
		t.Fatalf("args = %q", cfg.Args)
	}
	if cfg.MemoryLimit != 512<<20 || cfg.FileSizeLimit != 0 {
		t.Fatalf("memory %d, file size %d", cfg.MemoryLimit, cfg.FileSizeLimit)
	}
	if cfg.RuntimeMax != time.Hour || cfg.StartTimeout != 10*time.Second {
		t.Fatalf("runtime %s, start %s", cfg.RuntimeMax, cfg.StartTimeout)
	}
	if cfg.Protocol != phptaintipc.ProtocolVersion || cfg.Limits.MaxFrameBytes != phptaintipc.MaxFrameBytes {
		t.Fatalf("protocol %d, limits %+v", cfg.Protocol, cfg.Limits)
	}
}
