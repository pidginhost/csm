package workerproc

import (
	"context"
	"errors"
	"io"
	"os"
	"runtime"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestCallOwnsRequestDescriptorsUntilSendFinishes(t *testing.T) {
	for _, canceled := range []bool{false, true} {
		name := "timeout"
		if canceled {
			name = "canceled"
		}
		t.Run(name, func(t *testing.T) {
			timeout := 100 * time.Millisecond
			wantErr, losses := ErrTimeout, uint64(1)
			if canceled {
				timeout, wantErr, losses = 5*time.Second, context.Canceled, 0
			}
			s := newTestSupervisor(t, helperLauncher(t, "echo"), timeout)
			r, w, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			defer w.Close()
			otherR, otherW, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer otherR.Close()
			defer otherW.Close()

			entered, release := make(chan struct{}), make(chan struct{})
			finish := sync.OnceFunc(func() { close(release) })
			defer finish()
			sent := make(chan error, 1)
			s.child = &child{proc: exitedProcess(), conn: &fakeTransport{
				onSend: func(_ []byte, fds []*os.File) error {
					close(entered)
					<-release
					flags, sendErr := unix.FcntlInt(fds[0].Fd(), unix.F_GETFD, 0)
					if sendErr == nil && flags&unix.FD_CLOEXEC == 0 {
						sendErr = errors.New("request descriptor is not close-on-exec")
					}
					if sendErr == nil {
						_, sendErr = fds[0].Write([]byte("x"))
					}
					sent <- sendErr
					return sendErr
				},
				onReceive: func() (Frame, []*os.File, error) { return Frame{}, nil, nil },
			}}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			fds := []*os.File{w}
			done := make(chan error, 1)
			go func() {
				_, _, callErr := s.Call(ctx, Frame{Op: "work"}, fds, okCheck)
				done <- callErr
			}()
			select {
			case <-entered:
			case <-time.After(time.Second):
				t.Fatal("send did not start")
			}
			if canceled {
				cancel()
			}
			select {
			case callErr := <-done:
				if !errors.Is(callErr, wantErr) {
					t.Fatalf("Call = %v, want %v", callErr, wantErr)
				}
			case <-time.After(time.Second):
				t.Fatal("Call did not return while send was blocked")
			}
			if _, statErr := w.Stat(); statErr != nil {
				t.Fatalf("Call closed caller descriptor: %v", statErr)
			}
			// The caller may close its files and reuse its slice once Call returns.
			_ = w.Close()
			fds[0] = otherW
			finish()
			select {
			case sendErr := <-sent:
				if sendErr != nil {
					t.Fatalf("late send lost its descriptor: %v", sendErr)
				}
			case <-time.After(time.Second):
				t.Fatal("send did not finish")
			}
			waitWorkerQueueIdle(t, s, losses)
			if err := r.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
				t.Fatal(err)
			}
			got, readErr := io.ReadAll(r)
			if readErr != nil || string(got) != "x" {
				t.Fatalf("original pipe = %q, %v; want x then EOF", got, readErr)
			}
			if _, statErr := otherW.Stat(); statErr != nil {
				t.Fatalf("Call closed replacement caller descriptor: %v", statErr)
			}
		})
	}
}

func TestCallClosesDescriptorsOnEveryReplyError(t *testing.T) {
	badReply := errors.New("bad reply")
	for _, tc := range []struct {
		name  string
		frame Frame
		err   error
		check Check
	}{
		{name: "receive", err: badReply, check: okCheck},
		{name: "op", frame: Frame{Op: "unexpected"}, check: okCheck},
		{name: "error", frame: Frame{Error: "failed"}, check: okCheck},
		{name: "check", check: func(Frame, []*os.File) (bool, error) { return false, badReply }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newTestSupervisor(t, helperLauncher(t, "echo"), time.Second)
			r, w, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			defer w.Close()
			s.child = &child{proc: exitedProcess(), conn: &fakeTransport{onReceive: func() (Frame, []*os.File, error) {
				return tc.frame, []*os.File{w}, tc.err
			}}}
			if _, fds, callErr := s.Call(context.Background(), Frame{Op: "work"}, nil, tc.check); callErr == nil || fds != nil {
				t.Fatalf("rejected reply: fds=%d err=%v", len(fds), callErr)
			}
			if _, statErr := w.Stat(); !errors.Is(statErr, os.ErrClosed) {
				t.Fatalf("rejected reply descriptor was not closed: %v", statErr)
			}
			if st := s.Stats(); st.ConsecutiveFailures != 1 || s.child != nil {
				t.Fatalf("rejected reply did not retire worker: %+v", st)
			}
			waitWorkerQueueIdle(t, s, 1)
		})
	}
}

func TestCallReleasesRequestDescriptors(t *testing.T) {
	for _, mode := range []string{"success", "send-error", "send-exit", "receive-error", "closed-request"} {
		t.Run(mode, func(t *testing.T) {
			s := newTestSupervisor(t, helperLauncher(t, "echo"), 100*time.Millisecond)
			r, w, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			defer w.Close()
			requestFDs := []*os.File{w}
			if mode == "closed-request" {
				closed, pipeW, pipeErr := os.Pipe()
				if pipeErr != nil {
					t.Fatal(pipeErr)
				}
				_ = closed.Close()
				_ = pipeW.Close()
				requestFDs = append(requestFDs, closed)
			}
			s.child = &child{proc: exitedProcess(), conn: &fakeTransport{
				onSend: func(_ []byte, fds []*os.File) error {
					switch mode {
					case "send-error":
						return io.ErrClosedPipe
					case "send-exit":
						runtime.Goexit()
					}
					for _, f := range fds {
						if _, statErr := f.Stat(); statErr != nil {
							return statErr
						}
					}
					return nil
				},
				onReceive: func() (Frame, []*os.File, error) {
					if mode == "receive-error" {
						return Frame{}, nil, io.ErrUnexpectedEOF
					}
					return Frame{}, nil, nil
				},
			}}
			_, _, callErr := s.Call(context.Background(), Frame{Op: "work"}, requestFDs, okCheck)
			if (callErr == nil) != (mode == "success") {
				t.Fatalf("Call = %v", callErr)
			}
			losses := uint64(1)
			if mode == "success" {
				losses = 0
			}
			waitWorkerQueueIdle(t, s, losses)
			if _, statErr := w.Stat(); statErr != nil {
				t.Fatalf("Call closed caller descriptor: %v", statErr)
			}
			_ = w.Close()
			if err := r.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
				t.Fatal(err)
			}
			if _, readErr := r.Read(make([]byte, 1)); readErr != io.EOF {
				t.Fatalf("request descriptor leaked: %v, want EOF", readErr)
			}
		})
	}
}
