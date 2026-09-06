//go:build linux

package processhandle

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// EL8 and CloudLinux 8 ship 4.18 kernels without pidfd_open. Their
// pidfd_send_signal still accepts a /proc/<pid> directory descriptor, which
// pins the same struct pid, so the fallback stays race-free.
func forcePidfdOpenUnavailable(t *testing.T) {
	t.Helper()
	old := pidfdOpen
	t.Cleanup(func() { pidfdOpen = old })
	pidfdOpen = func(int, int) (int, error) { return -1, unix.ENOSYS }
}

func TestSignalUsesProcfsHandleWithoutPidfdOpen(t *testing.T) {
	forcePidfdOpenUnavailable(t)
	child := exec.Command("sleep", "60")
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = child.Process.Kill(); _ = child.Wait() })
	verified := 0
	if err := Signal(context.Background(), child.Process.Pid, syscall.SIGTERM, func() error { verified++; return nil }); err != nil {
		t.Fatal(err)
	}
	err := child.Wait()
	var exit *exec.ExitError
	if verified != 1 || !errors.As(err, &exit) || exit.Sys().(syscall.WaitStatus).Signal() != syscall.SIGTERM {
		t.Fatalf("verified=%d wait=%v", verified, err)
	}
}

// A process that exits while verification runs must invalidate the handle
// instead of letting a recycled PID inherit the signal.
func TestProcfsHandleRejectsExitDuringVerification(t *testing.T) {
	forcePidfdOpenUnavailable(t)
	child := exec.Command("sleep", "60")
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = child.Process.Kill(); _ = child.Wait() })
	verified := 0
	err := Signal(context.Background(), child.Process.Pid, syscall.SIGKILL, func() error {
		verified++
		if killErr := child.Process.Kill(); killErr != nil {
			return killErr
		}
		_ = child.Wait()
		return nil
	})
	if verified != 1 || !errors.Is(err, os.ErrProcessDone) {
		t.Fatalf("verified=%d error=%v", verified, err)
	}
}

// An unreaped child has already exited: it must not be reported as a live
// target, matching the pidfd poll contract.
func TestProcfsHandleTreatsZombieAsDone(t *testing.T) {
	forcePidfdOpenUnavailable(t)
	child := exec.Command("true")
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	pid := child.Process.Pid
	t.Cleanup(func() { _ = child.Wait() })
	var info unix.Siginfo
	if err := unix.Waitid(unix.P_PID, pid, &info, unix.WEXITED|unix.WNOWAIT, nil); err != nil {
		t.Fatal(err)
	}
	err := Signal(context.Background(), pid, syscall.SIGKILL, func() error {
		t.Fatal("verification ran for an exited process")
		return nil
	})
	if !errors.Is(err, os.ErrProcessDone) {
		t.Fatalf("error=%v", err)
	}
}

func TestProcfsAliveStatesAndDescriptorCleanup(t *testing.T) {
	for _, tc := range []struct {
		name, stat string
		wantDone   bool
		wantError  bool
	}{
		{name: "running", stat: "42 (name with ) and spaces) R 1 2 3"},
		{name: "zombie", stat: "42 (name) Z 1 2 3", wantDone: true},
		{name: "dead", stat: "42 (name) X 1 2 3", wantDone: true},
		{name: "dead lowercase", stat: "42 (name) x 1 2 3", wantDone: true},
		{name: "missing", wantDone: true},
		{name: "read error", wantError: true},
		{name: "parse error", stat: "malformed", wantError: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "stat")
			if tc.name == "read error" {
				if err := os.Mkdir(path, 0700); err != nil {
					t.Fatal(err)
				}
			} else if tc.stat != "" {
				if err := os.WriteFile(path, []byte(tc.stat), 0600); err != nil {
					t.Fatal(err)
				}
			}
			fd, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
			if err != nil {
				t.Fatal(err)
			}
			h := &handle{fd: fd, procfs: true}
			defer h.close()
			countFDs := func() int {
				entries, err := os.ReadDir("/proc/self/fd")
				if err != nil {
					t.Fatal(err)
				}
				return len(entries)
			}
			before := countFDs()
			for range 20 {
				err := h.alive()
				if errors.Is(err, os.ErrProcessDone) != tc.wantDone || (err != nil) != (tc.wantDone || tc.wantError) {
					t.Fatalf("alive: %v", err)
				}
			}
			if after := countFDs(); after != before {
				t.Fatalf("open descriptors grew from %d to %d", before, after)
			}
		})
	}
}

// A kernel without pidfd_send_signal has no safe path at all.
func TestSignalReportsUnsupportedWithoutPidfdSendSignal(t *testing.T) {
	forcePidfdOpenUnavailable(t)
	oldSend := pidfdSend
	t.Cleanup(func() { pidfdSend = oldSend })
	pidfdSend = func(int, unix.Signal, *unix.Siginfo, int) error { return unix.ENOSYS }
	child := exec.Command("sleep", "60")
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = child.Process.Kill(); _ = child.Wait() })
	err := Signal(context.Background(), child.Process.Pid, syscall.SIGKILL, func() error { return nil })
	if !errors.Is(err, ErrUnsupported) {
		t.Fatalf("error=%v", err)
	}
}

// The capability probe must agree with real signaling on both the pidfd_open
// path and the /proc fallback used by 4.18 kernels.
func TestProbeReportsCapabilityOnBothPaths(t *testing.T) {
	if err := probe(); err != nil {
		t.Fatalf("pidfd path unavailable: %v", err)
	}
	forcePidfdOpenUnavailable(t)
	if err := probe(); err != nil {
		t.Fatalf("procfs fallback unavailable: %v", err)
	}
	oldSend := pidfdSend
	t.Cleanup(func() { pidfdSend = oldSend })
	pidfdSend = func(int, unix.Signal, *unix.Siginfo, int) error { return unix.ENOSYS }
	if err := probe(); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("probe accepted a kernel without pidfd_send_signal: %v", err)
	}
}
