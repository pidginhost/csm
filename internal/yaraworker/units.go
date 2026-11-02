package yaraworker

import (
	"strconv"
	"time"

	"github.com/pidginhost/csm/internal/workerproc"
	"github.com/pidginhost/csm/internal/yaraipc"
)

// Unit name prefixes. Startup kills units left by a daemon that died,
// matching on the prefix plus "-".
const (
	ScanUnitPrefix    = "csm-yara-worker"
	CompileUnitPrefix = "csm-yara-compile-worker"
)

// ScanMemoryBase is the scan worker's memory cap before the largest content
// it may be handed: the loaded rules (179 MB for Forge full) plus headroom.
// The daemon adds the larger of its file and mail part size caps, because
// the worker reads a whole scan into memory.
const ScanMemoryBase = 512 << 20

// CompileMemoryLimit caps the compile worker. Compiling Forge full peaks at
// about 640 MB.
const CompileMemoryLimit = 1 << 30

// ScanUnitConfig is the locked-down unit the scan worker runs in. It writes
// no files. A relaunch reloads the rules, so it lives long: every restart
// costs a load of up to a few seconds.
func ScanUnitConfig(binary string, memoryLimit uint64, log func(string, ...any)) workerproc.UnitConfig {
	return unitConfig(binary, ScanUnitPrefix, memoryLimit, 0, 24*time.Hour, log)
}

// CompileUnitConfig is the locked-down unit one compile runs in. Its only
// file is the memfd holding the compiled rules.
func CompileUnitConfig(binary string, log func(string, ...any)) workerproc.UnitConfig {
	return unitConfig(binary, CompileUnitPrefix, CompileMemoryLimit, yaraipc.MaxSerializedRules, 5*time.Minute, log)
}

func unitConfig(binary, prefix string, memoryLimit, fileSizeLimit uint64, runtimeMax time.Duration, log func(string, ...any)) workerproc.UnitConfig {
	return workerproc.UnitConfig{
		Prefix:                prefix,
		Command:               binary,
		Args:                  []string{"yara-worker", "--memory-limit=" + strconv.FormatUint(memoryLimit, 10)},
		MemoryLimit:           memoryLimit,
		FileSizeLimit:         fileSizeLimit,
		RuntimeMax:            runtimeMax,
		StartTimeout:          10 * time.Second,
		Protocol:              yaraipc.ProtocolVersion,
		Limits:                workerproc.Limits{MaxFrameBytes: yaraipc.MaxFrameBytes},
		Log:                   log,
		AllowExecutableMemory: true,
	}
}
