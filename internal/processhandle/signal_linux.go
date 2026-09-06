//go:build linux

package processhandle

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"syscall"

	"golang.org/x/sys/unix"
)

var (
	pidfdOpen  = unix.PidfdOpen
	pidfdPoll  = unix.Poll
	pidfdSend  = unix.PidfdSendSignal
	pidfdClose = unix.Close
	procRoot   = "/proc"
)

// maxProcStatBytes bounds the tenant-visible /proc/<pid>/stat read. The comm
// field is capped at 16 bytes by the kernel, so a real record is far smaller.
const maxProcStatBytes = 4096

// procfs reports whether fd is a /proc/<pid> directory descriptor rather than
// a descriptor returned by pidfd_open. Both pin one struct pid, so
// pidfd_send_signal cannot be redirected to a recycled PID through either.
type handle struct {
	fd     int
	procfs bool
}

// openHandle pins the target process. pidfd_open needs Linux 5.3; the 4.18
// kernels on EL8 and CloudLinux 8 do not have it, but their pidfd_send_signal
// (Linux 5.1) accepts a /proc/<pid> directory descriptor, which pins the same
// struct pid. Falling back preserves the identity guarantee instead of
// disabling termination on every supported EL8 host.
func openHandle(pid int) (*handle, error) {
	fd, err := pidfdOpen(pid, 0)
	if err == nil {
		return &handle{fd: fd}, nil
	}
	if !errors.Is(err, unix.ENOSYS) {
		return nil, signalError("pidfd_open", err)
	}
	dirfd, dirErr := unix.Open(procRoot+"/"+strconv.Itoa(pid), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if dirErr != nil {
		if errors.Is(dirErr, unix.ENOENT) || errors.Is(dirErr, unix.ESRCH) {
			return nil, fmt.Errorf("open %s/%d: %w: %w", procRoot, pid, os.ErrProcessDone, dirErr)
		}
		return nil, fmt.Errorf("open %s/%d: %w (pidfd_open: %w)", procRoot, pid, dirErr, err)
	}
	return &handle{fd: dirfd, procfs: true}, nil
}

func (h *handle) close() { _ = pidfdClose(h.fd) }

func (h *handle) alive() error {
	if h.procfs {
		return h.procfsAlive()
	}
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

// procfsAlive reads the pinned directory's own stat file. A reaped process
// removes those entries, and an unreaped one reports a terminal state, so a
// replacement holding the same numeric PID is never mistaken for the target.
func (h *handle) procfsAlive() error {
	fd, err := unix.Openat(h.fd, "stat", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		if errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ESRCH) {
			return os.ErrProcessDone
		}
		return fmt.Errorf("open process state: %w", err)
	}
	// #nosec G115 -- Successful openat returns a non-negative file descriptor.
	file := os.NewFile(uintptr(fd), "stat")
	defer func() { _ = file.Close() }()
	data, err := io.ReadAll(io.LimitReader(file, maxProcStatBytes))
	if err != nil {
		if errors.Is(err, unix.ESRCH) {
			return os.ErrProcessDone
		}
		return fmt.Errorf("read process state: %w", err)
	}
	state, err := procStatState(data)
	if err != nil {
		return err
	}
	// Z: exited, awaiting reap. X/x: released. Neither can receive a signal.
	if state == 'Z' || state == 'X' || state == 'x' {
		return os.ErrProcessDone
	}
	return nil
}

// procStatState returns the third field of /proc/<pid>/stat. The second field
// is a process-controlled name in parentheses that may itself contain spaces
// and parentheses, so the scan starts at its final closing parenthesis.
func procStatState(data []byte) (byte, error) {
	end := bytes.LastIndexByte(data, ')')
	if end < 0 || end+2 >= len(data) || data[end+1] != ' ' {
		return 0, errors.New("unreadable process state")
	}
	return data[end+2], nil
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

// probe pins this process and asks the kernel to deliver signal 0, which
// validates the whole path (handle acquisition, liveness, delivery) without
// disturbing any process.
func probe() error {
	handle, err := openHandle(os.Getpid())
	if err != nil {
		return err
	}
	defer handle.close()
	if err := handle.alive(); err != nil {
		return err
	}
	return handle.signal(0)
}
