package workerproc

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"syscall"
	"testing"
	"time"
)

func TestCallCanceledBeforeDescriptorDuplication(t *testing.T) {
	for _, cause := range []error{context.Canceled, context.DeadlineExceeded} {
		t.Run(cause.Error(), func(t *testing.T) {
			s := newTestSupervisor(t, helperLauncher(t, "echo"), time.Second)
			r, w, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			defer w.Close()
			ctx, cancel := context.WithCancel(context.Background())
			if cause == context.DeadlineExceeded {
				cancel()
				ctx, cancel = context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
			}
			cancel()

			real := dupFD
			attempts := 0
			dupFD = func(int) (int, error) {
				attempts++
				return -1, syscall.EMFILE
			}
			defer func() { dupFD = real }()

			_, _, err = s.Call(ctx, Frame{Op: "work"}, []*os.File{w}, okCheck)
			if !errors.Is(err, cause) || errors.Is(err, ErrWorkerFailed) {
				t.Errorf("canceled Call = %v, want %v without a worker failure", err, cause)
			}
			if attempts != 0 {
				t.Errorf("canceled request attempted %d descriptor duplications", attempts)
			}
			if st := s.Stats(); st.Spawns != 0 || st.ConsecutiveFailures != 0 {
				t.Errorf("canceled request changed worker state: %+v", st)
			}
			waitWorkerQueueIdle(t, s, 0)
		})
	}
}

func TestCallRoundTripErrorsCannotBypassBreaker(t *testing.T) {
	for _, cause := range []error{context.Canceled, context.DeadlineExceeded, syscall.EMFILE, syscall.ENFILE, io.ErrUnexpectedEOF} {
		for _, phase := range []string{"send", "receive", "check", "error frame"} {
			t.Run(phase+"/"+cause.Error(), func(t *testing.T) {
				s := newTestSupervisor(t, helperLauncher(t, "echo"), time.Second)
				failure := fmt.Errorf("worker operation: %w", cause)
				wantText := "test worker: "
				conn := &fakeTransport{
					onReceive: func() (Frame, []*os.File, error) { return Frame{}, nil, nil },
				}
				check := okCheck
				switch phase {
				case "send":
					conn.onSend = func([]byte, []*os.File) error { return failure }
					wantText += "write request: "
				case "receive":
					conn.onReceive = func() (Frame, []*os.File, error) { return Frame{}, nil, failure }
					wantText += "read reply: "
				case "check":
					check = func(Frame, []*os.File) (bool, error) { return false, failure }
				case "error frame":
					conn.onReceive = func() (Frame, []*os.File, error) {
						return Frame{Error: failure.Error()}, nil, nil
					}
					wantText += "worker: "
				}
				wantText += failure.Error()
				for i := 1; i <= ConsecutiveFailureLimit; i++ {
					s.child = &child{proc: exitedProcess(), conn: conn}
					_, _, err := s.Call(context.Background(), Frame{Op: "work"}, nil, check)
					if !errors.Is(err, ErrWorkerFailed) {
						t.Errorf("Call = %v, want worker failure", err)
					}
					if wantCause := phase != "error frame"; errors.Is(err, cause) != wantCause {
						t.Errorf("Call = %v, want errors.Is(%v) = %t", err, cause, wantCause)
					}
					if err == nil || err.Error() != wantText {
						t.Errorf("Call text = %v, want %q", err, wantText)
					}
					if st := s.Stats(); st.ConsecutiveFailures != i || s.child != nil {
						t.Errorf("failure did not retire and count worker: %+v", st)
					}
				}
				if st := s.Stats(); !st.BreakerOpen {
					t.Errorf("repeated failures did not open breaker: %+v", st)
				}
				waitWorkerQueueIdle(t, s, ConsecutiveFailureLimit)
			})
		}
	}
}
