package checks

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/actionlog"
	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/processhandle"
)

func TestProcessUIDRejectsPrivilegedOrMalformedCredentials(t *testing.T) {
	for _, credentials := range []string{
		"1001\t0\t1001\t1001", "1001\t1001\t0\t1001", "1001\t1001\t1001\t0",
		"1001\t1001", "1001\tno\t1001\t1001", "1001\t4294967296\t1001\t1001",
	} {
		t.Run(credentials, func(t *testing.T) {
			old := osFS
			osFS = &mockOS{readFile: func(string) ([]byte, error) { return []byte("Uid:\t" + credentials + "\n"), nil }}
			t.Cleanup(func() { osFS = old })
			if uid := getProcessUID("4242"); uid != "" && uid != "0" {
				t.Fatalf("unsafe credentials accepted as UID %s", uid)
			}
		})
	}
}

// Checks policy tests still run verification after substituting kernel I/O.
// Actual pidfd ordering and exit races are tested in internal/processhandle.
type processSignalCalls struct {
	requested []int
	signaled  []int
}

func withSimulatedProcessSignal(t *testing.T) *processSignalCalls {
	t.Helper()
	calls := &processSignalCalls{}
	previous := signalProcess
	signalProcess = func(ctx context.Context, pid int, sig syscall.Signal, verify func() error) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		calls.requested = append(calls.requested, pid)
		if sig != syscall.SIGKILL {
			t.Fatalf("unexpected signal %v", sig)
		}
		if err := verify(); err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		calls.signaled = append(calls.signaled, pid)
		return nil
	}
	t.Cleanup(func() { signalProcess = previous })
	return calls
}

func TestAutoKillVerifiesCapturedProcess(t *testing.T) {
	for _, reason := range []string{"eligible", "root transition", "stale", "missing executable", "canceled"} {
		t.Run(reason, func(t *testing.T) {
			sink := withActionSink(t)
			calls := withSimulatedProcessSignal(t)
			proc := &procMock{uid: "1001", exe: "/tmp/evil", uptime: 1000, startTick: 10000}
			old := osFS
			osFS = proc
			t.Cleanup(func() { osFS = old })
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			when := time.Now().Add(-time.Second)
			switch reason {
			case "root transition":
				pinnedSignal := signalProcess
				signalProcess = func(ctx context.Context, pid int, sig syscall.Signal, verify func() error) error {
					return pinnedSignal(ctx, pid, sig, func() error { proc.uid = "0"; return verify() })
				}
			case "stale":
				when = time.Now().Add(-950 * time.Second)
			case "missing executable":
				proc.exe = ""
			case "canceled":
				cancel()
			}
			cfg := &config.Config{}
			cfg.AutoResponse.Enabled, cfg.AutoResponse.KillProcesses = true, true
			actions := AutoKillProcesses(ctx, cfg, []alert.Finding{{Check: "suspicious_process", PID: 4242, Severity: alert.Critical, Timestamp: when}})
			if len(sink.records) != 1 || sink.records[0].Op != "respond.kill_process" {
				t.Fatalf("kill records=%+v", sink.records)
			}
			want := 0
			if reason == "eligible" {
				want = 1
			}
			if len(actions) != want || len(calls.signaled) != want {
				t.Fatalf("actions=%+v signaled=%v, want=%d", actions, calls.signaled, want)
			}
			attempts := 1
			if reason == "canceled" {
				attempts = 0
			}
			if len(calls.requested) != attempts || attempts == 1 && calls.requested[0] != 4242 {
				t.Fatalf("handle requests=%v, want %d", calls.requested, attempts)
			}
		})
	}
}

func TestKillAndQuarantineReportsSignalOutcome(t *testing.T) {
	for _, reason := range []string{"eligible", "root transition", "unrelated process", "unsupported", "send failed", "canceled", "cancel after signal"} {
		t.Run(reason, func(t *testing.T) {
			dir := mustEvalSymlinks(t, t.TempDir())
			path, qdir := filepath.Join(dir, "payload"), filepath.Join(dir, "quarantine")
			if err := os.WriteFile(path, []byte("captured bytes"), 0600); err != nil {
				t.Fatal(err)
			}
			info, statErr := os.Lstat(path)
			if statErr != nil {
				t.Fatal(statErr)
			}
			previousRoots := fixQuarantineAllowedRoots
			fixQuarantineAllowedRoots = []string{dir}
			t.Cleanup(func() { fixQuarantineAllowedRoots = previousRoots })
			withQuarantineDirCF(t, qdir)
			proc := &procMock{uid: "1001", fds: map[string]string{"/proc/4242/fd/7": path}, stats: map[string]os.FileInfo{"/proc/4242/fd/7": info}, lstats: map[string]os.FileInfo{path: info}}
			old := osFS
			osFS = proc
			t.Cleanup(func() { osFS = old })
			sink := withActionSink(t)
			calls := withSimulatedProcessSignal(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch reason {
			case "root transition":
				pinnedSignal := signalProcess
				signalProcess = func(ctx context.Context, pid int, sig syscall.Signal, verify func() error) error {
					return pinnedSignal(ctx, pid, sig, func() error { proc.uid = "0"; return verify() })
				}
			case "unrelated process":
				proc.stats = nil
			case "unsupported":
				signalProcess = func(context.Context, int, syscall.Signal, func() error) error { return processhandle.ErrUnsupported }
			case "send failed":
				signalProcess = func(_ context.Context, _ int, _ syscall.Signal, verify func() error) error {
					if err := verify(); err != nil {
						return err
					}
					return syscall.EPERM
				}
			case "canceled":
				cancel()
			case "cancel after signal":
				pinnedSignal := signalProcess
				signalProcess = func(ctx context.Context, pid int, sig syscall.Signal, verify func() error) error {
					err := pinnedSignal(ctx, pid, sig, verify)
					cancel()
					return err
				}
			}
			result := fixKillAndQuarantine(ctx, path, "PID: 4242")
			wantResult := actionlog.Refused
			switch reason {
			case "eligible", "cancel after signal":
				wantResult = actionlog.Applied
			case "unsupported", "send failed", "canceled":
				wantResult = actionlog.Failed
			}
			if len(sink.records) == 0 || sink.records[0].Op != "respond.kill_process" || sink.records[0].Result != wantResult {
				t.Fatalf("kill records=%+v", sink.records)
			}
			wantRecords := 2
			if reason == "canceled" {
				wantRecords = 1
			}
			if len(sink.records) != wantRecords {
				t.Fatalf("records=%+v", sink.records)
			}
			if reason == "canceled" {
				if result.Success || result.Error == "" {
					t.Fatalf("canceled fix=%+v", result)
				}
				if _, err := os.Stat(path); err != nil {
					t.Fatalf("canceled fix changed original: %v", err)
				}
				if _, err := os.Stat(qdir); !os.IsNotExist(err) {
					t.Fatalf("canceled fix created quarantine: %v", err)
				}
				return
			}
			failed := reason == "unsupported" || reason == "send failed"
			if result.Success == failed || (result.Error != "") != failed {
				t.Fatalf("fix=%+v", result)
			}
			if _, err := os.Stat(path); !os.IsNotExist(err) {
				t.Fatalf("original was not quarantined: %v", err)
			}
			metas, err := filepath.Glob(filepath.Join(qdir, "*.meta"))
			if err != nil || len(metas) != 1 {
				t.Fatalf("recovery metadata=%v error=%v", metas, err)
			}
			wantSignals := 0
			if reason == "eligible" || reason == "cancel after signal" {
				wantSignals = 1
			}
			if len(calls.signaled) != wantSignals || strings.Contains(result.Action, "killed PID") != (wantSignals == 1) {
				t.Fatalf("signals=%v result=%+v", calls.signaled, result)
			}
		})
	}
}
