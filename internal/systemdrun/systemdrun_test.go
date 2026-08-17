package systemdrun

import (
	"strings"
	"testing"
	"time"
)

// The whole point of the wrapper is that PID 1 forks the command, so it escapes
// the caller's ProtectSystem=strict mount namespace and seccomp filters.
// --scope would keep the command as a child of the sandboxed process.
func TestArgvNeverUsesScope(t *testing.T) {
	name, args := Argv("/usr/bin/systemd-run", Options{}, "/bin/true")

	if name != "/usr/bin/systemd-run" {
		t.Fatalf("name = %q, want the resolved systemd-run path", name)
	}
	if strings.Contains(strings.Join(args, " "), "--scope") {
		t.Errorf("--scope inherits the caller's sandbox and must never be used: %v", args)
	}
}

// The wrapped command and its arguments must survive intact after the -- guard,
// otherwise systemd-run would try to interpret them as its own flags.
func TestArgvPassesCommandAfterSeparator(t *testing.T) {
	_, args := Argv("/usr/bin/systemd-run", Options{}, "exim", "-bpc")

	sep := -1
	for i, a := range args {
		if a == "--" {
			sep = i
			break
		}
	}
	if sep < 0 {
		t.Fatalf("argv must separate systemd-run flags from the command with --: %v", args)
	}
	if got := strings.Join(args[sep+1:], " "); got != "exim -bpc" {
		t.Errorf("command after -- = %q, want %q", got, "exim -bpc")
	}
}

// Without --pipe the unit's stdout goes to the journal, so a caller that needs
// to parse the output would read nothing.
func TestArgvPipesOutputWhenRequested(t *testing.T) {
	_, args := Argv("/usr/bin/systemd-run", Options{Pipe: true}, "exim", "-bpc")

	if !contains(args, "--pipe") {
		t.Errorf("Pipe option must add --pipe so stdout reaches the caller: %v", args)
	}
	if contains(args, "--wait") {
		t.Errorf("--pipe already waits, so argv must not also include --wait: %v", args)
	}
}

// --pipe already implies waiting; without it the caller would return before the
// unit finished.
func TestArgvWaitsWhenNotPiping(t *testing.T) {
	_, args := Argv("/usr/bin/systemd-run", Options{}, "/bin/true")

	if !contains(args, "--wait") {
		t.Errorf("a non-piping unit must be waited on: %v", args)
	}
}

func TestArgvSetsRuntimeMax(t *testing.T) {
	_, args := Argv("/usr/bin/systemd-run", Options{RuntimeMax: 90 * time.Second}, "/bin/true")

	if !contains(args, "--property=RuntimeMaxSec=90s") {
		t.Errorf("RuntimeMax must become a RuntimeMaxSec property: %v", args)
	}
}

func TestArgvPreservesFractionalRuntimeMax(t *testing.T) {
	for _, tc := range []struct {
		duration time.Duration
		want     string
	}{
		{duration: 1500 * time.Millisecond, want: "--property=RuntimeMaxSec=1.5s"},
		{duration: 500 * time.Millisecond, want: "--property=RuntimeMaxSec=0.5s"},
		{duration: time.Nanosecond, want: "--property=RuntimeMaxSec=0.000001s"},
	} {
		_, args := Argv("/usr/bin/systemd-run", Options{RuntimeMax: tc.duration}, "/bin/true")
		if !contains(args, tc.want) {
			t.Errorf("RuntimeMax %s must remain a valid non-zero time span: %v", tc.duration, args)
		}
	}
}

func TestArgvOmitsRuntimeMaxWhenZero(t *testing.T) {
	_, args := Argv("/usr/bin/systemd-run", Options{}, "/bin/true")

	for _, a := range args {
		if strings.HasPrefix(a, "--property=RuntimeMaxSec") {
			t.Errorf("zero RuntimeMax must not set a runtime limit: %v", args)
		}
	}
}

// On a host without systemd there is nothing to wrap, so the command runs
// directly rather than failing.
func TestArgvRunsCommandDirectlyWithoutSystemdRun(t *testing.T) {
	name, args := Argv("", Options{Pipe: true}, "exim", "-bpc")

	if name != "exim" {
		t.Errorf("name = %q, want the command itself", name)
	}
	if strings.Join(args, " ") != "-bpc" {
		t.Errorf("args = %v, want the command's own arguments", args)
	}
}

func contains(args []string, want string) bool {
	for _, a := range args {
		if a == want {
			return true
		}
	}
	return false
}
