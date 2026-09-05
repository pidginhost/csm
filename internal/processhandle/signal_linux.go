//go:build linux

package processhandle

import (
	"errors"
	"fmt"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

var (
	pidfdOpen  = unix.PidfdOpen
	pidfdPoll  = unix.Poll
	pidfdSend  = unix.PidfdSendSignal
	pidfdClose = unix.Close
)

type handle struct{ fd int }

func openHandle(pid int) (*handle, error) {
	fd, err := pidfdOpen(pid, 0)
	if err != nil {
		return nil, signalError("pidfd_open", err)
	}
	return &handle{fd: fd}, nil
}

func (h *handle) close() { _ = pidfdClose(h.fd) }

func (h *handle) alive() error {
	// #nosec G115 -- Linux file descriptors are non-negative signed C ints.
	fds := []unix.PollFd{{Fd: int32(h.fd), Events: unix.POLLIN}}
	if _, err := pidfdPoll(fds, 0); err != nil {
		return fmt.Errorf("poll process handle: %w", err)
	}
	if fds[0].Revents&(unix.POLLIN|unix.POLLHUP) != 0 {
		return os.ErrProcessDone
	}
	if fds[0].Revents != 0 {
		return fmt.Errorf("invalid process handle poll events: %#x", fds[0].Revents)
	}
	return nil
}

func (h *handle) signal(sig syscall.Signal) error {
	if err := pidfdSend(h.fd, sig, nil, 0); err != nil {
		return signalError("pidfd_send_signal", err)
	}
	return nil
}

func signalError(operation string, err error) error {
	if errors.Is(err, unix.ENOSYS) {
		return fmt.Errorf("%s: %w: %w", operation, ErrUnsupported, err)
	}
	if errors.Is(err, unix.ESRCH) {
		return fmt.Errorf("%s: %w: %w", operation, os.ErrProcessDone, err)
	}
	return fmt.Errorf("%s: %w", operation, err)
}
