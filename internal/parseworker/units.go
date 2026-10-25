package parseworker

import (
	"strconv"
	"time"

	"github.com/pidginhost/csm/internal/workerproc"
)

// DefaultMemoryLimit caps a parse worker's memory and swap together when
// nothing else is configured: the zip lister and the CLI always use it.
const DefaultMemoryLimit = 512 << 20

// UnitConfig is the locked-down unit a parse worker runs in: binary is the
// csm executable, prefix names the units, memoryLimit caps memory and swap,
// fileSizeLimit bounds what the worker may write into a memfd. The daemon
// and the CLI share it.
func UnitConfig(binary, prefix string, memoryLimit, fileSizeLimit uint64, log func(string, ...any)) workerproc.UnitConfig {
	return workerproc.UnitConfig{
		Prefix:        prefix,
		Command:       binary,
		Args:          []string{"parse-worker", "--memory-limit=" + strconv.FormatUint(memoryLimit, 10)},
		MemoryLimit:   memoryLimit,
		FileSizeLimit: fileSizeLimit,
		RuntimeMax:    time.Hour,
		StartTimeout:  10 * time.Second,
		Protocol:      ProtocolVersion,
		Limits:        Limits,
		Log:           log,
	}
}
