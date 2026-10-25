package parseworker

import (
	"testing"
	"time"
)

func TestUnitConfigForTheZipPool(t *testing.T) {
	cfg := UnitConfig("/opt/csm/csm", "csm-parse-worker-zip0", DefaultMemoryLimit, 64<<20, nil)
	if cfg.Command != "/opt/csm/csm" || cfg.Prefix != "csm-parse-worker-zip0" {
		t.Fatalf("command/prefix = %q %q", cfg.Command, cfg.Prefix)
	}
	if len(cfg.Args) != 2 || cfg.Args[0] != "parse-worker" || cfg.Args[1] != "--memory-limit=536870912" {
		t.Fatalf("args = %q", cfg.Args)
	}
	if cfg.MemoryLimit != 512<<20 || cfg.FileSizeLimit != 64<<20 || cfg.RuntimeMax != time.Hour ||
		cfg.StartTimeout != 10*time.Second || cfg.Protocol != ProtocolVersion || cfg.Limits != Limits {
		t.Fatalf("config = %+v", cfg)
	}
}

func TestUnitConfigMemoryLimitFollowsArgument(t *testing.T) {
	cfg := UnitConfig("/opt/csm/csm", "csm-parse-worker-mail0", 256<<20, 25<<20, nil)
	if cfg.MemoryLimit != 268435456 {
		t.Fatalf("memory limit = %d, want 268435456", cfg.MemoryLimit)
	}
	if len(cfg.Args) != 2 || cfg.Args[1] != "--memory-limit=268435456" {
		t.Fatalf("args = %q", cfg.Args)
	}
}
