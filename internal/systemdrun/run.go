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
// When systemd-run cannot be used -- not installed, or a harmless probe fails
// while the caller's context remains active -- the command runs directly
// instead. That is no worse than not having the wrapper at all, and it is the
// only honest option: giving up would disable the command entirely on a host
// where it might still work.
//
// The caller's command is attempted at most once. Its exit status and output
// cannot be told apart from systemd-run's own (--wait and --pipe propagate the
// unit's status and output verbatim), so a failure is never retried: running it
// again would repeat side effects like freezing or removing queued mail, and
// would mask the real error.
func Run(ctx context.Context, lookPath LookPathFunc, run RunnerFunc, opt Options, name string, args ...string) ([]byte, error) {
	systemdRunPath, _ := lookPath("systemd-run")
	if ctxErr := ctx.Err(); ctxErr != nil {
		return nil, ctxErr
	}
	if systemdRunPath == "" {
		return run(ctx, name, args...)
	}

	// Probe with a command that has no side effects, so the decision to fall
	// back is made before the caller's command has had a chance to run.
	probeName, probeArgs := Argv(systemdRunPath, opt, probeCommand)
	_, probeErr := run(ctx, probeName, probeArgs...)
	if ctxErr := ctx.Err(); ctxErr != nil {
		return nil, ctxErr
	}
	if probeErr != nil {
		return run(ctx, name, args...)
	}

	wrappedName, wrappedArgs := Argv(systemdRunPath, opt, name, args...)
	return run(ctx, wrappedName, wrappedArgs...)
}

// probeCommand is the no-op used to test whether systemd-run can start a unit.
// /bin/true is part of coreutils, which systemd itself depends on.
const probeCommand = "/bin/true"
