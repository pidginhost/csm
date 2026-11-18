package main

import (
	"bufio"
	"context"
	"errors"
	"io"
	"os"
	"os/signal"
	"syscall"

	"golang.org/x/sys/unix"
)

func withStalwartTerminal(ask func(io.Reader) error) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGHUP, syscall.SIGTERM, syscall.SIGQUIT, syscall.SIGTSTP, syscall.SIGPIPE)
	defer stop()
	return withStalwartTerminalInput(ctx, os.Stdin, ask)
}

func withStalwartTerminalInput(ctx context.Context, in *os.File, ask func(io.Reader) error) (err error) {
	fd := int(in.Fd())
	saved, err := unix.IoctlGetTermios(fd, getTerminalAttrs)
	if err != nil {
		return err
	}
	// Wake a blocked terminal read on interruption so we restore echo before
	// returning to the shell. A terminal hangup also wakes poll.
	wake, notify, err := os.Pipe()
	if err != nil {
		return err
	}
	defer wake.Close()
	defer notify.Close()
	stopWake := context.AfterFunc(ctx, func() { _ = notify.Close() })
	defer stopWake()

	hidden := *saved
	hidden.Lflag &^= unix.ECHO | unix.ECHONL
	// Keep a signal from flushing a ready line between poll and read. The
	// error path flushes pending input when it restores the terminal.
	hidden.Lflag |= unix.ICANON | unix.ISIG | unix.NOFLSH
	hidden.Iflag |= unix.ICRNL
	if err = unix.IoctlSetTermios(fd, setTerminalAttrs, &hidden); err != nil {
		return err
	}
	defer func() {
		var restoreErr error
		if err != nil {
			// Do not leave a partially typed password for the shell.
			restoreErr = unix.IoctlSetTermios(fd, flushTerminalAttrs, saved)
		} else {
			restoreErr = unix.IoctlSetTermios(fd, setTerminalAttrs, saved)
		}
		if restoreErr != nil {
			err = errors.Join(err, restoreErr)
		}
	}()
	r := stalwartTerminalReader{
		ctx: ctx,
		in:  in,
		fds: []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}, {Fd: int32(wake.Fd()), Events: unix.POLLIN}}, // #nosec G115 -- POSIX file descriptors fit in int32.
	}
	// A canonical terminal returns at most one line per read. The buffer
	// avoids a poll and a system call for each byte of that line.
	if err = ask(bufio.NewReader(&r)); err != nil {
		return err
	}
	return ctx.Err()
}

type stalwartTerminalReader struct {
	ctx context.Context
	in  *os.File
	fds []unix.PollFd
}

func (r *stalwartTerminalReader) Read(p []byte) (int, error) {
	for {
		_, err := unix.Poll(r.fds, -1)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return 0, err
		}
		if err := r.ctx.Err(); err != nil {
			return 0, err
		}
		return r.in.Read(p)
	}
}
