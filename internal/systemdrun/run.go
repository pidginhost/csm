package systemdrun

import "context"

// LookPathFunc resolves an executable, returning a non-nil error when it is not
// installed. Callers inject their own so tests do not depend on the host.
type LookPathFunc func(file string) (string, error)

// RunnerFunc executes a command and returns its output. Callers inject the
// runner their package already uses, which keeps command execution behind one
// abstraction per package instead of two.
type RunnerFunc func(ctx context.Context, name string, args ...string) ([]byte, error)

// Run executes name/args as a transient unit forked by PID 1, so the command
// escapes the caller's service sandbox, and returns its output.
//
// When systemd-run is not installed there is no sandbox to escape and the
// command runs directly. When systemd-run is installed but cannot reach the
// system bus (a container, a chroot), the command is retried directly. A
// non-zero exit from the command itself is returned as-is and never retried:
// running it twice would double any side effect and hide the real error.
func Run(ctx context.Context, lookPath LookPathFunc, run RunnerFunc, opt Options, name string, args ...string) ([]byte, error) {
	systemdRunPath, _ := lookPath("systemd-run")
	if systemdRunPath != "" {
		wrappedName, wrappedArgs := Argv(systemdRunPath, opt, name, args...)
		out, err := run(ctx, wrappedName, wrappedArgs...)
		if err == nil {
			return out, nil
		}
		if !Unavailable(out, err) {
			return out, err
		}
	}
	return run(ctx, name, args...)
}
