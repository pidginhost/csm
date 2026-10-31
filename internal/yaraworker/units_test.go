package yaraworker

import (
	"slices"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/yaraipc"
)

func TestScanUnitConfig(t *testing.T) {
	cfg := ScanUnitConfig("/opt/csm/csm", 528<<20, nil)
	if cfg.Command != "/opt/csm/csm" || cfg.Prefix != "csm-yara-worker" {
		t.Fatalf("command %q prefix %q", cfg.Command, cfg.Prefix)
	}
	if !slices.Equal(cfg.Args, []string{"yara-worker", "--memory-limit=553648128"}) {
		t.Fatalf("args = %q", cfg.Args)
	}
	if cfg.MemoryLimit != 528<<20 || cfg.FileSizeLimit != 0 {
		t.Fatalf("memory %d, file size %d", cfg.MemoryLimit, cfg.FileSizeLimit)
	}
	if cfg.RuntimeMax != 24*time.Hour || cfg.StartTimeout != 10*time.Second {
		t.Fatalf("runtime %s, start %s", cfg.RuntimeMax, cfg.StartTimeout)
	}
	if cfg.Protocol != yaraipc.ProtocolVersion || cfg.Limits.MaxFrameBytes != yaraipc.MaxFrameBytes {
		t.Fatalf("protocol %d, limits %+v", cfg.Protocol, cfg.Limits)
	}
	if !cfg.AllowExecutableMemory {
		t.Fatal("YARA-X cannot load rules without executable memory")
	}
}

func TestCompileUnitConfig(t *testing.T) {
	cfg := CompileUnitConfig("/opt/csm/csm", nil)
	if cfg.Command != "/opt/csm/csm" || cfg.Prefix != "csm-yara-compile-worker" {
		t.Fatalf("command %q prefix %q", cfg.Command, cfg.Prefix)
	}
	if !slices.Equal(cfg.Args, []string{"yara-worker", "--memory-limit=1073741824"}) {
		t.Fatalf("args = %q", cfg.Args)
	}
	if cfg.MemoryLimit != 1<<30 || cfg.FileSizeLimit != yaraipc.MaxSerializedRules {
		t.Fatalf("memory %d, file size %d", cfg.MemoryLimit, cfg.FileSizeLimit)
	}
	if cfg.RuntimeMax != 5*time.Minute || cfg.StartTimeout != 10*time.Second {
		t.Fatalf("runtime %s, start %s", cfg.RuntimeMax, cfg.StartTimeout)
	}
	if cfg.Protocol != yaraipc.ProtocolVersion || !cfg.AllowExecutableMemory {
		t.Fatalf("protocol %d, executable memory %v", cfg.Protocol, cfg.AllowExecutableMemory)
	}
}
