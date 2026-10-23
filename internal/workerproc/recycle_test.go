package workerproc

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

func newRecycleSupervisor(t *testing.T, cfg Config) *Supervisor {
	t.Helper()
	cfg.Name = "test worker"
	cfg.Timeout = 5 * time.Second
	cfg.Limits = Limits{MaxFrameBytes: 1 << 20, MaxFDs: 4}
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Stop() })
	return s
}

// sleepHandler sleeps for the number of milliseconds in the payload.
func sleepHandler(_ context.Context, req Frame, _ []*os.File) (Frame, []*os.File) {
	var ms int
	if err := json.Unmarshal(req.Payload, &ms); err != nil {
		return Frame{Error: err.Error()}, nil
	}
	time.Sleep(time.Duration(ms) * time.Millisecond)
	return Frame{Payload: json.RawMessage(`{}`)}, nil
}

func sleepCall(t *testing.T, s *Supervisor, ms int) {
	t.Helper()
	payload, _ := json.Marshal(ms)
	if _, _, err := s.Call(context.Background(), Frame{Op: "sleep", Payload: payload}, nil, okCheck); err != nil {
		t.Fatal(err)
	}
}

func TestCallRecyclesAfterMaxJobs(t *testing.T) {
	s := newRecycleSupervisor(t, Config{Launch: pairLauncher(t, sleepHandler), MaxJobs: 2})
	for range 5 {
		sleepCall(t, s, 0)
	}
	if st := s.Stats(); st.Spawns != 3 || st.ConsecutiveFailures != 0 {
		t.Fatalf("stats = %+v, want 3 spawns and no failures", st)
	}
	waitWorkerQueueIdle(t, s, 0)
}

// retiringProcess asks to retire after its first job.
type retiringProcess struct {
	Process
	asked atomic.Bool
}

func (p *retiringProcess) Retire() bool { return !p.asked.Swap(true) }

func TestCallRecyclesWhenWorkerAsksToRetire(t *testing.T) {
	inner := pairLauncher(t, sleepHandler)
	var first Process
	launch := func(ctx context.Context) (Process, error) {
		p, err := inner(ctx)
		if err != nil {
			return nil, err
		}
		if first == nil {
			first = &retiringProcess{Process: p}
			return first, nil
		}
		return p, nil
	}
	s := newRecycleSupervisor(t, Config{Launch: launch})
	sleepCall(t, s, 0)
	sleepCall(t, s, 0)
	if got := s.Stats().Spawns; got != 2 {
		t.Fatalf("spawns = %d, want a new worker after retirement", got)
	}
	select {
	case <-first.Done():
	default:
		t.Fatal("retired worker still running")
	}
	if got := s.Stats().ConsecutiveFailures; got != 0 {
		t.Fatalf("retirement counted as failure: %d", got)
	}
}

func TestIdleWorkerIsStopped(t *testing.T) {
	s := newRecycleSupervisor(t, Config{Launch: pairLauncher(t, sleepHandler), IdleTimeout: 50 * time.Millisecond})
	sleepCall(t, s, 0)
	if !s.Stats().Running {
		t.Fatal("worker not running after a call")
	}
	deadline := time.Now().Add(2 * time.Second)
	for s.Stats().Running {
		if time.Now().After(deadline) {
			t.Fatal("idle worker was not stopped")
		}
		time.Sleep(5 * time.Millisecond)
	}
	sleepCall(t, s, 0)
	if got := s.Stats().Spawns; got != 2 {
		t.Fatalf("spawns = %d, want 2", got)
	}
}

func TestIdleTimerSparesBusyWorker(t *testing.T) {
	s := newRecycleSupervisor(t, Config{Launch: pairLauncher(t, sleepHandler), IdleTimeout: time.Hour})
	sleepCall(t, s, 0)
	fired, finished := make(chan struct{}), make(chan struct{})
	s.mu.Lock()
	s.idle.Stop()
	s.lastUse = time.Now().Add(-s.cfg.IdleTimeout)
	s.idle = time.AfterFunc(time.Hour, func() {
		close(fired)
		s.stopIdle()
		close(finished)
	})
	timer := s.idle
	s.mu.Unlock()
	// Expire the previous idle deadline while Call holds the lock validating
	// a reply, then let that callback observe the freshly completed request.
	_, _, err := s.Call(context.Background(), Frame{Op: "sleep", Payload: json.RawMessage(`0`)}, nil, func(Frame, []*os.File) (bool, error) {
		timer.Reset(0)
		waitIdleCallback(t, fired)
		return false, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	waitIdleCallback(t, finished)
	if st := s.Stats(); st.Spawns != 1 || !st.Running || st.ConsecutiveFailures != 0 {
		t.Fatalf("idle callback did not spare the busy worker: %+v", st)
	}
	waitWorkerQueueIdle(t, s, 0)
}

func TestStopCancelsIdleTimer(t *testing.T) {
	for _, order := range []string{"pending", "stop first", "idle first", "concurrent"} {
		t.Run(order, func(t *testing.T) {
			s := newRecycleSupervisor(t, Config{Launch: pairLauncher(t, sleepHandler), IdleTimeout: time.Hour})
			sleepCall(t, s, 0)
			fired, release, finished := make(chan struct{}), make(chan struct{}), make(chan struct{})
			releaseCallback := sync.OnceFunc(func() { close(release) })
			defer releaseCallback()
			s.mu.Lock()
			s.idle.Stop()
			s.lastUse = time.Now().Add(-s.cfg.IdleTimeout)
			s.idle = time.AfterFunc(time.Hour, func() {
				close(fired)
				<-release
				s.stopIdle()
				close(finished)
			})
			timer := s.idle
			s.mu.Unlock()
			if order != "pending" {
				timer.Reset(0)
				waitIdleCallback(t, fired)
			}
			if order == "idle first" || order == "concurrent" {
				releaseCallback()
			}
			if order == "idle first" {
				waitIdleCallback(t, finished)
			}
			if err := s.Stop(); err != nil {
				t.Fatal(err)
			}
			if order == "stop first" || order == "pending" {
				releaseCallback()
			}
			if order != "pending" {
				waitIdleCallback(t, finished)
			} else if timer.Stop() {
				t.Fatal("Stop left the idle timer armed")
			}
			if st := s.Stats(); st.Running || st.ConsecutiveFailures != 0 || st.Spawns != 1 {
				t.Fatalf("unexpected state after Stop: %+v", st)
			}
			if _, _, err := s.Call(context.Background(), Frame{Op: "sleep", Payload: json.RawMessage(`0`)}, nil, okCheck); !errors.Is(err, ErrStopped) {
				t.Fatalf("Call after Stop = %v", err)
			}
			waitWorkerQueueIdle(t, s, 0)
		})
	}
}

func waitIdleCallback(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("idle callback did not progress")
	}
}

func TestRetirementPreservesReplyDescriptors(t *testing.T) {
	s := newRecycleSupervisor(t, Config{Launch: helperLauncher(t, "echo"), MaxJobs: 1})
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	for i := 1; i <= 2; i++ {
		reply, fds, err := s.Call(context.Background(), Frame{Op: "work", Payload: json.RawMessage(`7`)}, []*os.File{w}, okCheck)
		defer closeFiles(fds)
		if err != nil || string(reply.Payload) != "7" || len(fds) != 1 {
			t.Fatalf("retired reply: %+v, descriptors=%d, err=%v", reply, len(fds), err)
		}
		if st := s.Stats(); st.Running || st.Spawns != i || st.ConsecutiveFailures != 0 {
			t.Fatalf("retired worker state: %+v", st)
		}
		if _, err := fds[0].Write([]byte("x")); err != nil {
			t.Fatalf("retirement closed reply descriptor: %v", err)
		}
		if err := r.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
			t.Fatal(err)
		}
		var got [1]byte
		if n, err := r.Read(got[:]); err != nil || n != 1 || got[0] != 'x' {
			t.Fatalf("reply descriptor reached the wrong pipe: %q, %d, %v", got, n, err)
		}
	}
	waitWorkerQueueIdle(t, s, 0)
}

func TestRejectedCallsDoNotExtendWorkerIdleTime(t *testing.T) {
	for _, mode := range []string{"canceled", "oversize", "marshal", "descriptor"} {
		t.Run(mode, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				s := newRecycleSupervisor(t, Config{Launch: helperLauncher(t, "echo"), IdleTimeout: time.Minute})
				s.child = &child{proc: exitedProcess(), conn: &fakeTransport{
					onReceive: func() (Frame, []*os.File, error) { return Frame{}, nil, nil },
				}}
				sleepCall(t, s, 0)
				time.Sleep(30 * time.Second)
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				req := Frame{Op: "sleep", Payload: json.RawMessage(`0`)}
				var fds []*os.File
				switch mode {
				case "canceled":
					cancel()
				case "oversize":
					req.Payload = json.RawMessage(`"` + strings.Repeat("x", s.cfg.Limits.MaxFrameBytes) + `"`)
				case "marshal":
					req.Payload = json.RawMessage(`{`)
				case "descriptor":
					fds = []*os.File{nil}
				}
				if _, _, err := s.Call(ctx, req, fds, okCheck); err == nil {
					t.Fatal("invalid request accepted")
				}
				if !s.Stats().Running {
					t.Fatal("rejected request killed a healthy worker")
				}
				time.Sleep(30 * time.Second)
				synctest.Wait()
				if s.Stats().Running {
					t.Fatal("rejected request postponed idle retirement")
				}
			})
		})
	}
}

func TestWorkerRemovalDisarmsIdleTimer(t *testing.T) {
	for _, mode := range []string{"max jobs", "retire", "failure", "canceled", "spawn failure"} {
		t.Run(mode, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				s := newRecycleSupervisor(t, Config{
					Launch:      func(context.Context) (Process, error) { return nil, errors.New("no worker") },
					IdleTimeout: time.Hour,
					MaxJobs:     2,
				})
				ctx := context.Background()
				check := okCheck
				if mode != "spawn failure" {
					s.child = &child{proc: exitedProcess(), conn: &fakeTransport{
						onReceive: func() (Frame, []*os.File, error) { return Frame{}, nil, nil },
					}}
					sleepCall(t, s, 0)
					if s.idle == nil {
						t.Fatal("live worker has no idle timer")
					}
				}
				switch mode {
				case "retire":
					s.cfg.MaxJobs = 0
					s.child.proc = &retiringProcess{Process: s.child.proc}
				case "failure":
					check = func(Frame, []*os.File) (bool, error) { return false, errors.New("bad reply") }
				case "canceled":
					var cancel context.CancelFunc
					ctx, cancel = context.WithCancel(ctx)
					defer cancel()
					s.child.conn = &fakeTransport{onReceive: func() (Frame, []*os.File, error) {
						cancel()
						return Frame{}, nil, ctx.Err()
					}}
				}
				_, _, err := s.Call(ctx, Frame{Op: "work"}, nil, check)
				wantErr := mode == "failure" || mode == "canceled" || mode == "spawn failure"
				if (err != nil) != wantErr {
					t.Fatalf("Call = %v, want error: %t", err, wantErr)
				}
				if s.Stats().Running {
					t.Fatal("worker was not removed")
				}
				if s.idle != nil && s.idle.Stop() {
					t.Fatal("idle timer still retains a supervisor without a worker")
				}
				losses := uint64(0)
				if mode == "failure" || mode == "spawn failure" {
					losses = 1
				}
				waitWorkerQueueIdle(t, s, losses)
			})
		})
	}
}

func TestZeroLifespanSettingsKeepWorker(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := newRecycleSupervisor(t, Config{Launch: helperLauncher(t, "echo")})
		s.child = &child{proc: exitedProcess(), conn: &fakeTransport{
			onReceive: func() (Frame, []*os.File, error) { return Frame{}, nil, nil },
		}}
		for range 10 {
			sleepCall(t, s, 0)
			time.Sleep(time.Hour)
			synctest.Wait()
			if !s.Stats().Running || s.idle != nil {
				t.Fatal("zero lifespan settings retired the worker or armed an idle timer")
			}
		}
		waitWorkerQueueIdle(t, s, 0)
	})
}
