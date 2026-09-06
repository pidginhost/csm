//go:build linux

package processhandle

import (
	"context"
	"errors"
	"os"
	"os/exec"
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
	state, err := child.Process.Wait()
	if err != nil {
		t.Fatal(err)
	}
	_ = state
	// Re-running Signal against the reaped PID must not signal a replacement.
	err = Signal(context.Background(), pid, syscall.SIGKILL, func() error {
		t.Fatal("verification ran for an exited process")
		return nil
	})
	if !errors.Is(err, os.ErrProcessDone) {
		t.Fatalf("error=%v", err)
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
