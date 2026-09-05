//go:build linux

package processhandle

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"reflect"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// The numeric PID can be rebound while verification runs. Only the handle
// acquired beforehand may be signalled, and its exit invalidates verification.
func TestSignalKeepsCapturedProcessAcrossPIDReuse(t *testing.T) {
	for _, at := range []string{"verification", "send"} {
		t.Run(at, func(t *testing.T) {
			oldOpen, oldPoll, oldSend, oldClose := pidfdOpen, pidfdPoll, pidfdSend, pidfdClose
			t.Cleanup(func() { pidfdOpen, pidfdPoll, pidfdSend, pidfdClose = oldOpen, oldPoll, oldSend, oldClose })
			const pid, fd = 4242, 73
			current, captured := "original", ""
			alive, replacementSignals := true, 0
			var order []string
			pidfdOpen = func(got, flags int) (int, error) {
				if got != pid || flags != 0 {
					t.Fatalf("open=%d,%d", got, flags)
				}
				captured = current
				order = append(order, "open")
				return fd, nil
			}
			pidfdPoll = func(fds []unix.PollFd, timeout int) (int, error) {
				if len(fds) != 1 || fds[0].Fd != fd || timeout != 0 {
					t.Fatalf("poll=%+v timeout=%d", fds, timeout)
				}
				if !alive {
					fds[0].Revents = unix.POLLIN
					return 1, nil
				}
				return 0, nil
			}
			pidfdSend = func(got int, sig unix.Signal, info *unix.Siginfo, flags int) error {
				if got != fd || sig != unix.SIGKILL || info != nil || flags != 0 {
					t.Fatalf("send=%d,%d,%v,%d", got, sig, info, flags)
				}
				order = append(order, "send")
				current, alive = "replacement", false
				if captured == current {
					replacementSignals++
				}
				return unix.ESRCH
			}
			pidfdClose = func(got int) error {
				if got != fd {
					t.Fatalf("closed=%d", got)
				}
				order = append(order, "close")
				return nil
			}
			err := Signal(context.Background(), pid, syscall.SIGKILL, func() error {
				if captured != "original" {
					t.Fatal("verification happened before pinning")
				}
				order = append(order, "verify")
				if at == "verification" {
					current, alive = "replacement", false
				}
				return nil
			})
			if err == nil || replacementSignals != 0 || current != "replacement" {
				t.Fatalf("error=%v replacement signals=%d current=%s", err, replacementSignals, current)
			}
			want := []string{"open", "verify", "close"}
			if at == "send" {
				want = []string{"open", "verify", "send", "close"}
			}
			if !reflect.DeepEqual(order, want) {
				t.Fatalf("order=%v want=%v", order, want)
			}
		})
	}
}

func TestSignalRejectsCancellationVerificationAndUnavailableKernel(t *testing.T) {
	for _, at := range []string{"cancel before open", "cancel after verify", "reject", "old kernel", "denied handle", "exited", "poll error", "invalid handle", "send error"} {
		t.Run(at, func(t *testing.T) {
			oldOpen, oldPoll, oldSend, oldClose := pidfdOpen, pidfdPoll, pidfdSend, pidfdClose
			t.Cleanup(func() { pidfdOpen, pidfdPoll, pidfdSend, pidfdClose = oldOpen, oldPoll, oldSend, oldClose })
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if at == "cancel before open" {
				cancel()
			}
			opened, closed, verified, sent := 0, 0, 0, 0
			pidfdOpen = func(int, int) (int, error) {
				opened++
				switch at {
				case "old kernel":
					return -1, unix.ENOSYS
				case "denied handle":
					return -1, unix.EPERM
				}
				return 73, nil
			}
			pidfdPoll = func(fds []unix.PollFd, _ int) (int, error) {
				switch at {
				case "exited":
					fds[0].Revents = unix.POLLHUP
					return 1, nil
				case "poll error":
					return 0, unix.EIO
				case "invalid handle":
					fds[0].Revents = unix.POLLNVAL
					return 1, nil
				}
				return 0, nil
			}
			pidfdSend = func(int, unix.Signal, *unix.Siginfo, int) error { sent++; return unix.ENOSYS }
			pidfdClose = func(int) error { closed++; return nil }
			err := Signal(ctx, 4242, syscall.SIGKILL, func() error {
				verified++
				if at == "cancel after verify" {
					cancel()
				}
				if at == "reject" {
					return errors.New("identity changed")
				}
				return nil
			})
			if err == nil {
				t.Fatal("unsafe signal returned success")
			}
			wantOpen, wantClose, wantVerify, wantSend := 1, 1, 0, 0
			switch at {
			case "cancel before open":
				wantOpen, wantClose = 0, 0
			case "old kernel", "denied handle":
				wantClose = 0
			case "cancel after verify", "reject":
				wantVerify = 1
			case "send error":
				wantVerify, wantSend = 1, 1
			}
			if opened != wantOpen || closed != wantClose || verified != wantVerify || sent != wantSend {
				t.Fatalf("open/close/verify/send=%d/%d/%d/%d, want=%d/%d/%d/%d", opened, closed, verified, sent, wantOpen, wantClose, wantVerify, wantSend)
			}
			if (at == "old kernel" || at == "send error") && !errors.Is(err, ErrUnsupported) {
				t.Fatalf("missing unsupported diagnosis: %v", err)
			}
		})
	}
}

func TestSignalRealChild(t *testing.T) {
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

func TestSignalRealChildExitsDuringVerification(t *testing.T) {
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
