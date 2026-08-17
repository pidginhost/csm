package systemdrun

import (
	"context"
	"errors"
	"os/exec"
	"strings"
	"testing"
)

type recordedCall struct {
	name string
	args []string
}

func TestRunWrapsCommandWhenSystemdRunIsPresent(t *testing.T) {
	var calls []recordedCall
	lookPath := func(string) (string, error) { return "/usr/bin/systemd-run", nil }
	run := func(_ context.Context, name string, args ...string) ([]byte, error) {
		calls = append(calls, recordedCall{name, args})
		return []byte("29\n"), nil
	}

	out, err := Run(context.Background(), lookPath, run, Options{Pipe: true}, "exim", "-bpc")

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(out) != "29\n" {
		t.Errorf("output = %q, want the wrapped command's stdout", out)
	}
	if len(calls) != 2 || calls[0].name != "/usr/bin/systemd-run" || calls[1].name != "/usr/bin/systemd-run" {
		t.Fatalf("calls = %+v, want an availability probe then the wrapped command", calls)
	}
	if !strings.HasSuffix(strings.Join(calls[1].args, " "), "exim -bpc") {
		t.Errorf("args = %v, want the command at the end", calls[1].args)
	}
}

func TestRunCallsCommandDirectlyWhenSystemdRunIsMissing(t *testing.T) {
	var calls []recordedCall
	lookPath := func(string) (string, error) { return "", exec.ErrNotFound }
	run := func(_ context.Context, name string, args ...string) ([]byte, error) {
		calls = append(calls, recordedCall{name, args})
		return []byte("29\n"), nil
	}

	if _, err := Run(context.Background(), lookPath, run, Options{Pipe: true}, "exim", "-bpc"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(calls) != 1 || calls[0].name != "exim" {
		t.Fatalf("calls = %+v, want a single direct invocation", calls)
	}
}

func TestRunRetriesUnwrappedWhenSystemdRunCannotStartTheUnit(t *testing.T) {
	var calls []recordedCall
	lookPath := func(string) (string, error) { return "/usr/bin/systemd-run", nil }
	run := func(_ context.Context, name string, args ...string) ([]byte, error) {
		calls = append(calls, recordedCall{name, args})
		if name == "/usr/bin/systemd-run" {
			return []byte("Failed to connect to bus: No such file or directory"), errors.New("exit status 1")
		}
		return []byte("29\n"), nil
	}

	out, err := Run(context.Background(), lookPath, run, Options{Pipe: true}, "exim", "-bpc")

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(out) != "29\n" {
		t.Errorf("output = %q, want the retry's stdout", out)
	}
	if len(calls) != 2 || calls[1].name != "exim" {
		t.Fatalf("calls = %+v, want a wrapped attempt then a direct retry", calls)
	}
}

// Running the command twice on a genuine failure would double any side effect
// and hide the real error behind the retry's.
func TestRunDoesNotRetryWhenTheCommandItselfFails(t *testing.T) {
	var calls []recordedCall
	lookPath := func(string) (string, error) { return "/usr/bin/systemd-run", nil }
	run := func(_ context.Context, name string, args ...string) ([]byte, error) {
		calls = append(calls, recordedCall{name, args})
		if strings.HasSuffix(strings.Join(args, " "), "/bin/true") {
			return nil, nil
		}
		return []byte("exim: bad argument"), errors.New("exit status 2")
	}

	if _, err := Run(context.Background(), lookPath, run, Options{Pipe: true}, "exim", "-bpc"); err == nil {
		t.Fatal("a failing command must surface its error")
	}
	if len(calls) != 2 {
		t.Fatalf("calls = %+v, want an availability probe and one command invocation", calls)
	}
}

// A command can emit the same text as a systemd-run bus diagnostic. Once the
// command has started, that text must never trigger a direct retry: mutating
// commands such as buildeximconf and exim queue actions are not retry-safe.
func TestRunDoesNotRetryCommandThatPrintsBusFailure(t *testing.T) {
	var calls []recordedCall
	lookPath := func(string) (string, error) { return "/usr/bin/systemd-run", nil }
	run := func(_ context.Context, name string, args ...string) ([]byte, error) {
		calls = append(calls, recordedCall{name, args})
		if strings.HasSuffix(strings.Join(args, " "), "/bin/true") {
			return nil, nil
		}
		return []byte("Failed to connect to bus: application dependency unavailable"), errors.New("exit status 1")
	}

	if _, err := Run(context.Background(), lookPath, run, Options{Pipe: true}, "exim", "-Mrm", "id"); err == nil {
		t.Fatal("the wrapped command failure must be returned")
	}
	if len(calls) != 2 {
		t.Fatalf("calls = %+v, want a harmless probe and exactly one command invocation", calls)
	}
	if calls[0].name != "/usr/bin/systemd-run" || calls[1].name != "/usr/bin/systemd-run" {
		t.Fatalf("calls = %+v, wrapped command must not be retried directly", calls)
	}
}

// A probe can fail for reasons that have nothing to do with the bus: a minimal
// image without /bin/true, or a systemd-run too old for a flag. Giving up there
// would disable the command entirely, which is strictly worse than running it
// directly -- the same thing that happens on a host with no systemd-run at all.
func TestRunFallsBackWhenProbeFailsForAnyReason(t *testing.T) {
	var calls []recordedCall
	lookPath := func(string) (string, error) { return "/usr/bin/systemd-run", nil }
	run := func(_ context.Context, name string, args ...string) ([]byte, error) {
		calls = append(calls, recordedCall{name, args})
		if strings.HasSuffix(strings.Join(args, " "), "/bin/true") {
			return []byte("Failed to execute /bin/true: No such file or directory"), errors.New("exit status 203")
		}
		return []byte("29\n"), nil
	}

	out, err := Run(context.Background(), lookPath, run, Options{Pipe: true}, "exim", "-bpc")

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(out) != "29\n" {
		t.Errorf("output = %q, want the direct run's stdout", out)
	}
	if len(calls) != 2 || calls[1].name != "exim" {
		t.Fatalf("calls = %+v, want a failed probe then a direct run", calls)
	}
}
