package workerproc

import (
	"context"
	"encoding/json"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

// helperLauncher starts this test binary as a worker whose behaviour mode
// selects; TestHelperProcess is the child side.
func helperLauncher(t *testing.T, mode string) Launcher {
	t.Helper()
	return ExecLauncher(os.Args[0], []string{"-test.run=TestHelperProcess", "--"},
		append(os.Environ(), "CSM_WORKERPROC_HELPER="+mode))
}

// TestHelperProcess is not a real test. It is the child process the
// launcher and supervisor tests spawn.
func TestHelperProcess(t *testing.T) {
	mode := os.Getenv("CSM_WORKERPROC_HELPER")
	if mode == "" {
		t.Skip("not a helper invocation")
	}
	if mode == "exit" {
		os.Exit(3)
	}
	conn, err := ChildConn()
	if err != nil {
		t.Fatal(err)
	}
	lim := Limits{MaxFrameBytes: 1 << 20, MaxFDs: 8}
	receive := func() {
		if _, fds, err := ReceiveFrame(conn, lim); err != nil {
			t.Fatalf("read helper request: %v", err)
		} else {
			closeFiles(fds)
		}
	}
	send := func(f Frame, fds []*os.File) {
		if err := SendFrame(conn, f, fds, lim.MaxFrameBytes); err != nil {
			t.Fatalf("write helper reply: %v", err)
		}
	}
	switch {
	case mode == "echo":
		_ = Serve(context.Background(), conn, lim, func(_ context.Context, req Frame, fds []*os.File) (Frame, []*os.File) {
			out := make([]*os.File, 0, len(fds))
			for _, f := range fds {
				fd, err := syscall.Dup(int(f.Fd()))
				if err != nil {
					closeFiles(out)
					return Frame{Error: err.Error()}, nil
				}
				out = append(out, os.NewFile(uintptr(fd), "dup"))
			}
			return Frame{Payload: req.Payload}, out
		})
	case mode == "hang":
		// Spin without ever answering. This is what a parser loop looks like
		// from the outside: alive, burning a core, never replying. It must not
		// be reachable by SIGTERM either, which is why the handler is ignored.
		signal.Ignore(syscall.SIGTERM)
		receive()
		// Spinning at 100% CPU is exactly the condition under test: a parser
		// loop that neither returns nor responds to a catchable signal. A
		// sleeping stand-in would be stopped by things that cannot stop the
		// real thing, so the test would pass without proving containment.
		//nolint:staticcheck // SA5002: the busy loop is the fixture, not an oversight.
		for {
		}
	case mode == "sockcheck":
		var st0, st1 syscall.Stat_t
		err0, err1 := syscall.Fstat(0, &st0), syscall.Fstat(1, &st1)
		receive()
		out, _ := json.Marshal(struct {
			Socket bool `json:"socket"`
			Same   bool `json:"same"`
		}{
			Socket: err0 == nil && err1 == nil && st0.Mode&syscall.S_IFMT == syscall.S_IFSOCK && st1.Mode&syscall.S_IFMT == syscall.S_IFSOCK,
			Same:   err0 == nil && err1 == nil && st0.Dev == st1.Dev && st0.Ino == st1.Ino,
		})
		send(Frame{Payload: out}, nil)
	case mode == "reply-op":
		receive()
		send(Frame{Op: "x", Payload: json.RawMessage(`{}`)}, nil)
	case mode == "reply-error":
		receive()
		send(Frame{Error: "boom"}, nil)
	case strings.HasPrefix(mode, "fds:"):
		n, err := strconv.Atoi(strings.TrimPrefix(mode, "fds:"))
		if err != nil {
			t.Fatal(err)
		}
		receive()
		files := make([]*os.File, 0, n)
		for range n {
			r, w, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			_ = r.Close()
			files = append(files, w)
		}
		send(Frame{Payload: json.RawMessage(`{}`)}, files)
	default:
		t.Fatalf("unknown helper mode %q", mode)
	}
}
