package worker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/antispam"
	"github.com/pidginhost/csm/internal/systemdrun"
)

// Run launches this executable, so the test process also serves as the worker.
func TestMain(m *testing.M) {
	if filepath.Base(os.Args[0]) == "systemd-run" {
		// Stand-in for systemd-run: run the command after "--" in place.
		for i, arg := range os.Args {
			if arg == "--" && i+1 < len(os.Args) {
				// #nosec G204 -- test helper; argv comes from Run in this package.
				_ = syscall.Exec(os.Args[i+1], os.Args[i+1:], os.Environ())
			}
		}
		os.Exit(2)
	}
	if len(os.Args) != 2 {
		os.Exit(m.Run())
	}
	if os.Args[1] == "antispam-test-pipe-holder" {
		ready := os.Getenv("CSM_ANTISPAM_TEST_READY")
		if err := os.WriteFile(ready, nil, 0o600); err != nil {
			os.Exit(2)
		}
		for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); {
			if _, err := os.Stat(ready + ".release"); err == nil {
				if err := os.WriteFile(ready+".done", nil, 0o600); err != nil {
					os.Exit(2)
				}
				os.Exit(0)
			}
			time.Sleep(10 * time.Millisecond)
		}
		os.Exit(2)
	}
	if os.Args[1] != Command {
		os.Exit(m.Run())
	}
	switch os.Getenv("CSM_ANTISPAM_TEST_MODE") {
	case "protocol":
		tr := &fakeTransactor{result: antispam.Result{OK: true, Generation: "g2"}}
		var out bytes.Buffer
		code := Handle(os.Stdin, &out, tr, freeLock)
		want := antispam.Settings{DryRun: false, Socket: "/var/run/rspamd/scan.sock", RejectScore: 20, TagScore: 8}
		if len(tr.applied) != 1 || tr.applied[0] != want || tr.removed != 0 {
			os.Exit(2)
		}
		if _, err := os.Stdout.Write(out.Bytes()); err != nil {
			os.Exit(2)
		}
		os.Exit(code)
	case "oversized":
		fmt.Fprintf(os.Stdout, "%s", `{"operation":"remove","ok":true}`+strings.Repeat(" ", 2<<20))
		os.Exit(0)
	case "stderr":
		fmt.Fprintf(os.Stderr, "%s", strings.Repeat("x", 2<<20))
		os.Exit(1)
	case "wait":
		time.Sleep(5 * time.Second)
		os.Exit(0)
	case "inherited pipes":
		// Model a transient unit that keeps the descriptors after systemd-run dies.
		child := exec.Command(os.Args[0], "antispam-test-pipe-holder")
		child.Stdout, child.Stderr = os.Stdout, os.Stderr
		if err := child.Start(); err != nil {
			os.Exit(2)
		}
		if err := child.Wait(); err != nil {
			os.Exit(2)
		}
		os.Exit(0)
	}
	os.Exit(2)
}

// launchWorker makes Run find a systemd-run that is this test binary, so the
// worker runs through the same wrapped argv as in production.
func launchWorker(t *testing.T, mode string) {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	bin := t.TempDir()
	if err := os.Symlink(self, filepath.Join(bin, "systemd-run")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin)
	t.Setenv("CSM_ANTISPAM_TEST_MODE", mode)
}

func TestRunSendsRequestThroughStdin(t *testing.T) {
	launchWorker(t, "protocol")
	settings := antispam.Settings{DryRun: false, Socket: "/var/run/rspamd/scan.sock", RejectScore: 20, TagScore: 8}
	result, err := Run(context.Background(), antispam.ApplyRequest(settings))
	if err != nil || !result.OK || result.Operation != antispam.OpApply || result.Generation != "g2" {
		t.Fatalf("result=%+v err=%v", result, err)
	}
}

func TestRunRejectsRelativeSystemdRunLookup(t *testing.T) {
	launchWorker(t, "protocol")
	bin := os.Getenv("PATH")
	t.Chdir(filepath.Dir(bin))
	t.Setenv("PATH", "./"+filepath.Base(bin))
	t.Setenv("GODEBUG", "execerrdot=1")
	if _, err := exec.LookPath("systemd-run"); !errors.Is(err, exec.ErrDot) {
		t.Fatalf("lookup error=%v, want exec.ErrDot", err)
	}
	settings := antispam.Settings{DryRun: false, Socket: "/var/run/rspamd/scan.sock", RejectScore: 20, TagScore: 8}
	result, err := Run(context.Background(), antispam.ApplyRequest(settings))
	if result != (antispam.Result{}) || !errors.Is(err, systemdrun.ErrUnavailable) || !errors.Is(err, exec.ErrDot) {
		t.Fatalf("result=%+v err=%v, want rejected lookup without a worker result", result, err)
	}
}

// A complete JSON prefix must not hide output that exceeded the capture limit.
func TestRunRejectsOversizedOutput(t *testing.T) {
	launchWorker(t, "oversized")
	result, err := Run(context.Background(), antispam.RemoveRequest())
	if err == nil || result != (antispam.Result{}) || !strings.Contains(err.Error(), "output exceeds") {
		t.Fatalf("result=%+v err=%v", result, err)
	}
}

func TestRunBoundsProcessDiagnostics(t *testing.T) {
	launchWorker(t, "stderr")
	_, err := Run(context.Background(), antispam.RemoveRequest())
	var exitErr *exec.ExitError
	want := "antispam worker failed: exit status 1: " + strings.Repeat("x", maxStderr)
	if !errors.As(err, &exitErr) || err.Error() != want {
		t.Fatalf("err=%v", err)
	}
}

func TestRunReportsActiveDeadline(t *testing.T) {
	launchWorker(t, "wait")
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	_, err := Run(ctx, antispam.RemoveRequest())
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err=%v, want context.DeadlineExceeded", err)
	}
}

func TestRunCancellationBoundsInheritedPipes(t *testing.T) {
	launchWorker(t, "inherited pipes")
	ready := filepath.Join(t.TempDir(), "ready")
	t.Setenv("CSM_ANTISPAM_TEST_READY", ready)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	finished := make(chan error, 1)
	go func() {
		_, err := Run(ctx, antispam.RemoveRequest())
		finished <- err
	}()
	t.Cleanup(func() {
		if err := os.WriteFile(ready+".release", nil, 0o600); err != nil {
			t.Error(err)
		}
		for deadline := time.Now().Add(5 * time.Second); ; {
			if _, err := os.Stat(ready + ".done"); err == nil {
				break
			}
			if time.Now().After(deadline) {
				t.Error("pipe holder did not stop")
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
	})
	for deadline := time.Now().Add(5 * time.Second); ; {
		if _, err := os.Stat(ready); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("pipe holder did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	select {
	case err := <-finished:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("err=%v, want context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		if err := os.WriteFile(ready+".release", nil, 0o600); err != nil {
			t.Fatal(err)
		}
		<-finished
		t.Fatal("cancellation waited for a descendant to close its pipes")
	}
}

func TestRunReportsDeadline(t *testing.T) {
	launchWorker(t, "inherited pipes")
	ready := filepath.Join(t.TempDir(), "ready")
	t.Setenv("CSM_ANTISPAM_TEST_READY", ready)
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	_, err := Run(ctx, antispam.RemoveRequest())
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err=%v, want context.DeadlineExceeded", err)
	}
	if _, err := os.Stat(ready); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expired context started the worker: %v", err)
	}
}

func systemdRun(string) (string, error) { return "/usr/bin/systemd-run", nil }

func TestRunUsesFixedBoundedTransientCommand(t *testing.T) {
	var calls [][]string
	result, err := execute(context.Background(), "/opt/csm/csm", systemdRun, func(_ context.Context, name string, args ...string) ([]byte, error) {
		calls = append(calls, append([]string{name}, args...))
		if len(calls) == 2 {
			return []byte(`{"operation":"remove","ok":true}` + "\n"), nil
		}
		return nil, nil
	})
	want := [][]string{
		{"/usr/bin/systemd-run", "--quiet", "--collect", "--pipe", "--property=RuntimeMaxSec=300s", "--", "/bin/true"},
		{"/usr/bin/systemd-run", "--quiet", "--collect", "--pipe", "--property=RuntimeMaxSec=300s", "--", "/opt/csm/csm", "antispam-worker"},
	}
	if err != nil || !result.OK || !reflect.DeepEqual(calls, want) {
		t.Fatalf("result=%+v err=%v calls=%q", result, err, calls)
	}
}

// The worker exits 1 for a busy or failed transaction and still prints its
// result; the caller needs that result, not a generic failure.
func TestRunReturnsResultFromFailedExit(t *testing.T) {
	exit := errors.New("exit status 1")
	result, err := execute(context.Background(), "/opt/csm/csm", systemdRun, func(_ context.Context, name string, args ...string) ([]byte, error) {
		if args[len(args)-1] == "/bin/true" {
			return nil, nil
		}
		return []byte(`{"operation":"apply","ok":false,"busy":true,"failed_step":"lock","rollback":"none","error":"held"}` + "\n"), exit
	})
	if err != nil || !result.Busy || result.OK || result.FailedStep != "lock" {
		t.Fatalf("result=%+v err=%v", result, err)
	}
}

func TestRunReportsMissingResult(t *testing.T) {
	crash := errors.New("signal: killed: worker stack")
	for name, tc := range map[string]struct {
		out  string
		err  error
		want string
	}{
		"crash":          {"", crash, "worker stack"},
		"clean exit":     {"", nil, "returned no result"},
		"garbled out":    {"partial {", nil, "returned no result"},
		"null":           {"null", nil, "returned no result"},
		"empty object":   {"{}", nil, "returned no result"},
		"missing status": {`{"operation":"remove"}`, nil, "returned no result"},
		"null status":    {`{"operation":"remove","ok":null}`, nil, "returned no result"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := execute(context.Background(), "/opt/csm/csm", systemdRun, func(_ context.Context, name string, args ...string) ([]byte, error) {
				if args[len(args)-1] == "/bin/true" {
					return nil, nil
				}
				return []byte(tc.out), tc.err
			})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want it to mention %q", err, tc.want)
			}
		})
	}
}

// The daemon and the worker agree on the wire format: a request built by
// the daemon decodes in Handle, and Handle's output parses in Run.
func TestRunAndHandleShareTheProtocol(t *testing.T) {
	settings := antispam.Settings{DryRun: false, Socket: "/var/run/rspamd/scan.sock", RejectScore: 20, TagScore: 8}
	body, err := json.Marshal(antispam.ApplyRequest(settings))
	if err != nil {
		t.Fatal(err)
	}
	tr := &fakeTransactor{result: antispam.Result{OK: true, Generation: "g2"}}
	result, err := execute(context.Background(), "/opt/csm/csm", systemdRun,
		func(_ context.Context, name string, args ...string) ([]byte, error) {
			if args[len(args)-1] == "/bin/true" {
				return nil, nil
			}
			if name != "/usr/bin/systemd-run" || !reflect.DeepEqual(args[len(args)-3:], []string{"--", "/opt/csm/csm", Command}) {
				t.Fatalf("ran %s %q", name, args)
			}
			var out bytes.Buffer
			Handle(bytes.NewReader(body), &out, tr, freeLock)
			return out.Bytes(), nil
		})
	if err != nil || !result.OK || result.Operation != antispam.OpApply || result.Generation != "g2" ||
		len(tr.applied) != 1 || tr.applied[0] != settings {
		t.Fatalf("result=%+v err=%v transactor=%+v", result, err, tr)
	}
}

func TestClipBoundsDiagnostics(t *testing.T) {
	if got := clip("  " + strings.Repeat("x", 2*maxStderr) + "\n"); len(got) != maxStderr {
		t.Fatalf("len = %d", len(got))
	}
}

func TestCappedBufferDrainsWithoutRetainingExcess(t *testing.T) {
	b := cappedBuffer{limit: maxStderr}
	want := "a" + strings.Repeat("b", maxStderr-1)
	for i, chunk := range []string{"a", want[1:], "c", strings.Repeat("d", 2*maxStderr)} {
		p := []byte(chunk)
		if n, err := b.Write(p); n != len(p) || err != nil {
			t.Fatalf("Write=%d, %v, want %d, nil", n, err, len(p))
		}
		if b.exceeded != (i >= 2) {
			t.Fatalf("write %d exceeded=%v", i, b.exceeded)
		}
	}
	if string(b.data) != want || !b.exceeded {
		t.Fatalf("retained=%d exceeded=%v", len(b.data), b.exceeded)
	}
	if n, err := b.Write(nil); n != 0 || err != nil || len(b.data) != maxStderr {
		t.Fatalf("empty Write=%d, %v retained=%d", n, err, len(b.data))
	}
}

// The worker edits /etc as root; inside the daemon sandbox it would fail
// halfway. Without a working systemd-run it must not start at all.
func TestRunNeverStartsTheWorkerInsideTheSandbox(t *testing.T) {
	for name, tc := range map[string]struct {
		lookup     systemdrun.LookPathFunc
		wantProbes int
	}{
		"missing":      {func(string) (string, error) { return "", exec.ErrNotFound }, 0},
		"probe failed": {systemdRun, 1},
	} {
		t.Run(name, func(t *testing.T) {
			var calls [][]string
			_, err := execute(context.Background(), "/opt/csm/csm", tc.lookup, func(_ context.Context, name string, args ...string) ([]byte, error) {
				calls = append(calls, append([]string{name}, args...))
				return nil, errors.New("Failed to connect to bus")
			})
			if !errors.Is(err, systemdrun.ErrUnavailable) || len(calls) != tc.wantProbes {
				t.Fatalf("err=%v calls=%q", err, calls)
			}
		})
	}
}
