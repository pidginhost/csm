// Package systemdrun builds argv for running a command outside the calling
// service's systemd sandbox.
//
// CSM's daemon runs under ProtectSystem=strict with a narrow ReadWritePaths
// allow-list. Heavyweight system tools write paths that allow-list cannot
// reasonably enumerate, and some refuse to start at all when a path they need
// is read-only. Handing such a command to systemd-run makes PID 1 fork it as a
// transient unit, outside csm.service's mount namespace and seccomp filters.
//
// Never use --scope for this: scope mode wraps a child of the sandboxed
// process, so it inherits exactly the restrictions the wrapper exists to
// escape.
package systemdrun

import (
	"fmt"
	"strings"
	"time"
)

// Options tunes how the transient unit is run.
type Options struct {
	// Pipe connects the unit's stdio to the caller so its output can be
	// captured. Without it the unit's stdout goes to the journal and the
	// caller reads nothing. --pipe already implies waiting for the unit.
	Pipe bool
	// RuntimeMax bounds the unit's lifetime via RuntimeMaxSec. Zero omits the
	// property, leaving the unit unbounded.
	RuntimeMax time.Duration
}

// Argv returns the argv that runs name/args as a transient unit. When
// systemdRunPath is empty -- systemd-run is not installed, so there is no
// sandbox to escape either -- the command's own argv is returned unchanged.
func Argv(systemdRunPath string, opt Options, name string, args ...string) (string, []string) {
	if systemdRunPath == "" {
		return name, args
	}
	flags := []string{"--quiet", "--collect"}
	if opt.Pipe {
		flags = append(flags, "--pipe")
	} else {
		flags = append(flags, "--wait")
	}
	if opt.RuntimeMax > 0 {
		flags = append(flags, "--property=RuntimeMaxSec="+formatRuntimeMax(opt.RuntimeMax))
	}
	flags = append(flags, "--")
	flags = append(flags, name)
	return systemdRunPath, append(flags, args...)
}

func formatRuntimeMax(d time.Duration) string {
	// systemd time spans have microsecond granularity. Round a positive
	// sub-microsecond duration up so it never becomes the special zero value,
	// then render fractional seconds without float rounding.
	microseconds := d / time.Microsecond
	if d%time.Microsecond != 0 {
		microseconds++
	}
	seconds := microseconds / 1_000_000
	fraction := microseconds % 1_000_000
	if fraction == 0 {
		return fmt.Sprintf("%ds", seconds)
	}
	fractionText := strings.TrimRight(fmt.Sprintf("%06d", fraction), "0")
	return fmt.Sprintf("%d.%ss", seconds, fractionText)
}
