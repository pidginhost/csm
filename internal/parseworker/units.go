package parseworker

import (
	"strconv"
	"time"

	"github.com/pidginhost/csm/internal/workerproc"
)

// unitMemoryLimit caps a parse worker's memory and swap together.
const unitMemoryLimit = 512 << 20

// UnitConfig is the locked-down unit a parse worker runs in: binary is the
// csm executable, prefix names the units. The daemon and the CLI share it.
func UnitConfig(binary, prefix string, log func(string, ...any)) workerproc.UnitConfig {
	return workerproc.UnitConfig{
		Prefix:        prefix,
		Command:       binary,
		Args:          []string{"parse-worker", "--memory-limit=" + strconv.Itoa(unitMemoryLimit)},
		MemoryLimit:   unitMemoryLimit,
		FileSizeLimit: 64 << 20,
		RuntimeMax:    time.Hour,
		StartTimeout:  10 * time.Second,
		Protocol:      ProtocolVersion,
		Limits:        Limits,
		Log:           log,
	}
}
