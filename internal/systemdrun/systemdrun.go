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
	"errors"
	"fmt"
	"os/exec"
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
		flags = append(flags, fmt.Sprintf("--property=RuntimeMaxSec=%ds", int(opt.RuntimeMax.Seconds())))
	}
	flags = append(flags, "--")
	flags = append(flags, name)
	return systemdRunPath, append(flags, args...)
}

// Unavailable reports whether a failed wrapped run means systemd-run itself
// could not start the unit, in which case the caller should retry the command
// directly. A non-zero exit from the wrapped command is a real failure and is
// never reported here -- retrying that would run the command twice and mask the
// error.
func Unavailable(output []byte, err error) bool {
	if errors.Is(err, exec.ErrNotFound) {
		return true
	}
	lower := strings.ToLower(string(output))
	for _, needle := range []string{
		"failed to connect to bus",
		"failed to create bus connection",
		"system has not been booted with systemd",
	} {
		if strings.Contains(lower, needle) {
			return true
		}
	}
	return false
}
