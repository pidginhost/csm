package phptaintworker

import (
	"strconv"
	"time"

	"github.com/pidginhost/csm/internal/phptaintipc"
	"github.com/pidginhost/csm/internal/workerproc"
)

// DefaultMemoryLimit caps the worker's memory and swap together.
const DefaultMemoryLimit = 512 << 20

// UnitConfig is the locked-down unit the PHP taint worker runs in: binary is
// the csm executable, prefix names the units. The worker writes no files, so
// it may not grow any.
func UnitConfig(binary, prefix string, log func(string, ...any)) workerproc.UnitConfig {
	return workerproc.UnitConfig{
		Prefix:        prefix,
		Command:       binary,
		Args:          []string{"phptaint-worker", "--memory-limit=" + strconv.Itoa(DefaultMemoryLimit)},
		MemoryLimit:   DefaultMemoryLimit,
		FileSizeLimit: 0,
		RuntimeMax:    time.Hour,
		StartTimeout:  10 * time.Second,
		Protocol:      phptaintipc.ProtocolVersion,
		Limits:        workerproc.Limits{MaxFrameBytes: phptaintipc.MaxFrameBytes},
		Log:           log,
	}
}
