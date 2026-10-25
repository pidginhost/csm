package workerproc

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
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
				if phase == "error frame" {
					// Worker text is quoted so it cannot forge log lines.
					wantText += strconv.Quote(failure.Error())
				} else {
					wantText += failure.Error()
				}
				local := phase != "error frame" && (errors.Is(cause, syscall.EMFILE) || errors.Is(cause, syscall.ENFILE))
				for i := 1; i <= ConsecutiveFailureLimit; i++ {
					s.child = &child{proc: liveProcess(), conn: conn}
					_, _, err := s.Call(context.Background(), Frame{Op: "work"}, nil, check)
					if errors.Is(err, ErrWorkerFailed) == local {
						t.Errorf("Call = %v, want worker failure = %v", err, !local)
					}
					if wantCause := phase != "error frame"; errors.Is(err, cause) != wantCause {
						t.Errorf("Call = %v, want errors.Is(%v) = %t", err, cause, wantCause)
					}
					if err == nil || err.Error() != wantText {
						t.Errorf("Call text = %v, want %q", err, wantText)
					}
					wantFailures := i
					if local {
						wantFailures = 0
					}
					if st := s.Stats(); st.ConsecutiveFailures != wantFailures || s.child != nil {
						t.Errorf("failure did not retire and count worker: %+v", st)
					}
				}
				if st := s.Stats(); st.BreakerOpen == local {
					t.Errorf("breaker state = %+v, want open = %v", st, !local)
				}
				waitWorkerQueueIdle(t, s, ConsecutiveFailureLimit)
			})
		}
	}
}

func TestCallLocalRoundTripExhaustionDoesNotReportJob(t *testing.T) {
	for _, cause := range []error{syscall.EMFILE, syscall.ENFILE} {
		for _, phase := range []string{"send", "receive", "check"} {
			t.Run(phase+"/"+cause.Error(), func(t *testing.T) {
				s := newTestSupervisor(t, pairLauncher(t, echoPayload), time.Second)
				conn := &fakeTransport{onReceive: func() (Frame, []*os.File, error) { return Frame{}, nil, nil }}
				check := okCheck
				switch phase {
				case "send":
					conn.onSend = func([]byte, []*os.File) error { return fmt.Errorf("send: %w", cause) }
				case "receive":
					conn.onReceive = func() (Frame, []*os.File, error) { return Frame{}, nil, fmt.Errorf("receive: %w", cause) }
				case "check":
					check = func(Frame, []*os.File) (bool, error) { return false, fmt.Errorf("check: %w", cause) }
				}
				s.child = &child{proc: liveProcess(), conn: conn}
				reports := 0
				s.cfg.OnJob = func(string, uint64) { reports++ }
				_, _, err := s.Call(context.Background(), Frame{Op: "work"}, nil, check)
				if !errors.Is(err, cause) || errors.Is(err, ErrWorkerFailed) || FailureReason(err) != "" {
					t.Errorf("local exhaustion counted as worker failure: %v", err)
				}
				if reports != 0 || s.Stats().ConsecutiveFailures != 0 {
					t.Errorf("local exhaustion reported %d jobs, stats %+v", reports, s.Stats())
				}
				if s.child != nil {
					t.Fatal("desynchronized worker retained")
				}
			})
		}
	}
}
