package workerproc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

func newTestSupervisor(t *testing.T, launch Launcher, timeout time.Duration) *Supervisor {
	t.Helper()
	s, err := New(Config{Name: "test worker", Launch: launch, Timeout: timeout, Limits: Limits{MaxFrameBytes: 1 << 20, MaxFDs: 4}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Stop() })
	return s
}

func okCheck(Frame, []*os.File) (bool, error) { return false, nil }

// modeLauncher starts helper workers in whatever mode *mode holds at launch,
// so a test can turn a hanging host into a healthy one between calls.
func modeLauncher(t *testing.T, mode *string) Launcher {
	return func(ctx context.Context) (Process, error) { return helperLauncher(t, *mode)(ctx) }
}

func TestCallKillsAndReapsAHungWorker(t *testing.T) {
	s := newTestSupervisor(t, helperLauncher(t, "hang"), 500*time.Millisecond)
	_, _, err := s.Call(context.Background(), Frame{Op: "work"}, nil, okCheck)
	if !errors.Is(err, ErrTimeout) {
		t.Fatalf("err = %v, want ErrTimeout", err)
	}
	pid := s.Stats().LastPID
	if err := syscall.Kill(pid, 0); err == nil {
		t.Fatalf("hung worker %d still exists", pid)
	}
	if got := s.Stats().ConsecutiveFailures; got != 1 {
		t.Fatalf("failures = %d", got)
	}
}

func TestCallPassesDescriptorsAndReusesHealthyWorker(t *testing.T) {
	s := newTestSupervisor(t, helperLauncher(t, "echo"), 5*time.Second)
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	for range 2 {
		reply, fds, err := s.Call(context.Background(), Frame{Op: "work", Payload: json.RawMessage(`7`)}, []*os.File{w}, okCheck)
		if err != nil || string(reply.Payload) != "7" || len(fds) != 1 {
			t.Fatalf("reply=%+v fds=%d err=%v", reply, len(fds), err)
		}
		_ = fds[0].Close()
	}
	if got := s.Stats().Spawns; got != 1 {
		t.Fatalf("spawns = %d, want one worker for both calls", got)
	}
}

func TestCallRejectsReplyWithOpOrError(t *testing.T) {
	for mode, want := range map[string]string{"reply-op": "response carries op", "reply-error": "boom"} {
		s := newTestSupervisor(t, helperLauncher(t, mode), 5*time.Second)
		_, _, err := s.Call(context.Background(), Frame{Op: "work"}, nil, okCheck)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("%s: err = %v", mode, err)
		}
		if s.Stats().ConsecutiveFailures != 1 {
			t.Fatalf("%s: rejected reply did not count", mode)
		}
	}
}

func TestCallCheckErrorClosesReplyDescriptors(t *testing.T) {
	s := newTestSupervisor(t, helperLauncher(t, "fds:2"), 5*time.Second)
	before := openFDs(t)
	_, fds, err := s.Call(context.Background(), Frame{Op: "work"}, nil, func(Frame, []*os.File) (bool, error) {
		return false, errors.New("bad reply")
	})
	if err == nil || fds != nil {
		t.Fatalf("rejected reply returned: fds=%d err=%v", len(fds), err)
	}
	assertNoFDLeak(t, before)
}

func TestCallRejectsTooManyReplyDescriptors(t *testing.T) {
	s := newTestSupervisor(t, helperLauncher(t, "fds:5"), 5*time.Second)
	before := openFDs(t)
	if _, fds, err := s.Call(context.Background(), Frame{Op: "work"}, nil, okCheck); err == nil || fds != nil {
		t.Fatalf("5 descriptors accepted with MaxFDs 4: fds=%d err=%v", len(fds), err)
	}
	assertNoFDLeak(t, before)
}

func TestCallClosesDescriptorsOfAbandonedReply(t *testing.T) {
	s := newTestSupervisor(t, func(context.Context) (Process, error) { return nil, errors.New("unused") }, 100*time.Millisecond)
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	// w is the pipe's only write end and is never closed by the test: once
	// the supervisor side closes it, r reads EOF.
	release := make(chan struct{})
	s.child = &child{proc: exitedProcess(), conn: &fakeTransport{onReceive: func() (Frame, []*os.File, error) {
		<-release
		return Frame{}, []*os.File{w}, nil
	}}}
	if _, _, err := s.Call(context.Background(), Frame{Op: "work"}, nil, okCheck); !errors.Is(err, ErrTimeout) {
		t.Fatalf("err = %v", err)
	}
	close(release)
	_ = r.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := r.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("descriptor of an abandoned reply was not closed: %v", err)
	}
}

func TestCallRefusesOversizeRequestWithoutSpawning(t *testing.T) {
	s := newTestSupervisor(t, helperLauncher(t, "echo"), time.Second)
	big := Frame{Op: "work", Payload: json.RawMessage(`"` + strings.Repeat("a", 1<<20) + `"`)}
	if _, _, err := s.Call(context.Background(), big, nil, okCheck); !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("err = %v", err)
	}
	if st := s.Stats(); st.Spawns != 0 || st.ConsecutiveFailures != 0 {
		t.Fatalf("oversize request touched the worker: %+v", st)
	}
	if q := s.QueueStatuses(time.Now())["requests"]; q.DroppedTotal != 0 {
		t.Fatalf("oversize request counted as loss: %+v", q)
	}
}

func TestCallLostReplyCountsLossNotBreaker(t *testing.T) {
	s := newTestSupervisor(t, helperLauncher(t, "echo"), 5*time.Second)
	if _, _, err := s.Call(context.Background(), Frame{Op: "work"}, nil, func(Frame, []*os.File) (bool, error) { return true, nil }); err != nil {
		t.Fatal(err)
	}
	if s.Stats().ConsecutiveFailures != 0 {
		t.Fatal("lost reply counted toward the breaker")
	}
	waitWorkerQueueIdle(t, s, 1)
}

func TestSupervisorBreakerRecoversAfterCooldown(t *testing.T) {
	mode := "hang"
	s := newTestSupervisor(t, modeLauncher(t, &mode), 200*time.Millisecond)

	clock := time.Now()
	s.now = func() time.Time { return clock }

	for i := 0; i < ConsecutiveFailureLimit; i++ {
		if _, _, err := s.Call(context.Background(), Frame{Op: "work"}, nil, okCheck); !errors.Is(err, ErrTimeout) {
			t.Fatalf("request %d err = %v, want ErrTimeout", i, err)
		}
	}

	// Still inside the cooldown: refused without spawning.
	spawns := s.Stats().Spawns
	if _, _, err := s.Call(context.Background(), Frame{Op: "work"}, nil, okCheck); err == nil || errors.Is(err, ErrTimeout) || isCanceled(err) {
		t.Fatalf("err during cooldown = %v, want a worker failure", err)
	}
	if s.Stats().Spawns != spawns {
		t.Fatal("spawned a worker while the breaker was open")
	}

	// Past the cooldown, with a healthy worker, the host recovers.
	clock = clock.Add(BreakerCooldown + time.Second)
	mode = "echo"
	if _, _, err := s.Call(context.Background(), Frame{Op: "work"}, nil, okCheck); err != nil {
		t.Fatalf("err after cooldown = %v, want success", err)
	}

	// And the counter is genuinely reset, not merely bypassed once.
	for i := 0; i < ConsecutiveFailureLimit+2; i++ {
		if _, _, err := s.Call(context.Background(), Frame{Op: "work"}, nil, okCheck); err != nil {
			t.Fatalf("post-recovery request %d err = %v, want success", i, err)
		}
	}
}

func TestSupervisorBreakerRetriesOncePerCooldown(t *testing.T) {
	s := newTestSupervisor(t, helperLauncher(t, "hang"), 200*time.Millisecond)

	clock := time.Now()
	s.now = func() time.Time { return clock }
	for i := 0; i < ConsecutiveFailureLimit; i++ {
		_, _, _ = s.Call(context.Background(), Frame{Op: "work"}, nil, okCheck)
	}

	spawns := s.Stats().Spawns
	for i := 0; i < 25; i++ {
		_, _, _ = s.Call(context.Background(), Frame{Op: "work"}, nil, okCheck)
	}
	if s.Stats().Spawns != spawns {
		t.Fatalf("spawned %d workers during one cooldown, want 0", s.Stats().Spawns-spawns)
	}

	clock = clock.Add(BreakerCooldown + time.Second)
	_, _, _ = s.Call(context.Background(), Frame{Op: "work"}, nil, okCheck)
	if s.Stats().Spawns != spawns+1 {
		t.Fatalf("spawns after cooldown = %d, want exactly one trial", s.Stats().Spawns-spawns)
	}

	// The failed trial restarts the cooldown. More files arriving immediately
	// must not turn the half-open state into an unbounded respawn loop.
	for i := 0; i < 25; i++ {
		_, _, _ = s.Call(context.Background(), Frame{Op: "work"}, nil, okCheck)
	}
	if s.Stats().Spawns != spawns+1 {
		t.Fatalf("spawned %d workers after a failed trial, want 0 until the next cooldown", s.Stats().Spawns-(spawns+1))
	}
}

func TestSupervisorCancelledTrialDoesNotFreeASpawn(t *testing.T) {
	s := newTestSupervisor(t, helperLauncher(t, "hang"), 5*time.Second)

	clock := time.Now()
	s.now = func() time.Time { return clock }

	shortCfg := 200 * time.Millisecond
	s.cfg.Timeout = shortCfg
	for i := 0; i < ConsecutiveFailureLimit; i++ {
		_, _, _ = s.Call(context.Background(), Frame{Op: "work"}, nil, okCheck)
	}
	s.cfg.Timeout = 5 * time.Second // ctx must win the race, not the deadline
	clock = clock.Add(BreakerCooldown + time.Second)

	spawns := s.Stats().Spawns
	canceled, refused := 0, 0
	for i := 0; i < 10; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		_, _, err := s.Call(ctx, Frame{Op: "work"}, nil, okCheck)
		cancel()
		switch {
		case isCanceled(err):
			canceled++
		case err != nil && !errors.Is(err, ErrTimeout):
			refused++
		default:
			t.Fatalf("request %d err = %v, want canceled or refused", i, err)
		}
	}
	// The first cancellation consumes the trial and re-arms the cooldown; the
	// rest are refused without forking, which is the whole point.
	if canceled != 1 || refused != 9 {
		t.Fatalf("canceled=%d refused=%d, want 1 and 9", canceled, refused)
	}
	if delta := s.Stats().Spawns - spawns; delta > 1 {
		t.Fatalf("cancelled requests spawned %d workers, want at most the one trial", delta)
	}
}

// pairLauncher runs h in this process on the far end of a socket pair, so a
// test can watch both ends of a descriptor it passes.
func pairLauncher(t *testing.T, h Handler) Launcher {
	t.Helper()
	return func(ctx context.Context) (Process, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		parent, far := socketPair(t)
		for _, c := range []*net.UnixConn{parent, far} {
			if err := c.SetDeadline(time.Time{}); err != nil {
				return nil, err
			}
		}
		p := &pairProcess{conn: parent, far: far, done: make(chan struct{})}
		go func() {
			defer close(p.done)
			_ = Serve(context.Background(), far, Limits{MaxFrameBytes: 1 << 20, MaxFDs: 8}, h)
		}()
		return p, nil
	}
}

type pairProcess struct {
	conn, far *net.UnixConn
	done      chan struct{}
	kill      sync.Once
}

func (p *pairProcess) Conn() *net.UnixConn   { return p.conn }
func (p *pairProcess) Done() <-chan struct{} { return p.done }
func (p *pairProcess) PID() int              { return os.Getpid() }
func (p *pairProcess) Retire() bool          { return false }

func (p *pairProcess) Kill() error {
	p.kill.Do(func() { _ = p.far.Close() })
	return nil
}

func echoPayload(_ context.Context, req Frame, _ []*os.File) (Frame, []*os.File) {
	return Frame{Payload: req.Payload}, nil
}

func TestCallKeepsCallerPipeNonBlocking(t *testing.T) {
	s := newTestSupervisor(t, pairLauncher(t, echoPayload), 5*time.Second)
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	if _, _, err := s.Call(context.Background(), Frame{Op: "work", Payload: json.RawMessage(`1`)}, []*os.File{r}, okCheck); err != nil {
		t.Fatal(err)
	}
	assertPipeStillPollable(t, r)
}

func TestCallDescriptorExhaustionKeepsWorker(t *testing.T) {
	s := newTestSupervisor(t, pairLauncher(t, echoPayload), 5*time.Second)
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	if _, _, err := s.Call(context.Background(), Frame{Op: "work", Payload: json.RawMessage(`1`)}, nil, okCheck); err != nil {
		t.Fatal(err)
	}
	real := dupFD
	dupFD = func(int) (int, error) { return -1, syscall.EMFILE }
	defer func() { dupFD = real }()
	for range ConsecutiveFailureLimit + 1 {
		_, _, err := s.Call(context.Background(), Frame{Op: "work", Payload: json.RawMessage(`1`)}, []*os.File{w}, okCheck)
		if !errors.Is(err, syscall.EMFILE) || errors.Is(err, ErrWorkerFailed) {
			t.Fatalf("Call = %v, want local EMFILE", err)
		}
	}
	if st := s.Stats(); st.ConsecutiveFailures != 0 || st.BreakerOpen {
		t.Fatalf("descriptor exhaustion counted as worker failure: %+v", st)
	}
	waitWorkerQueueIdle(t, s, ConsecutiveFailureLimit+1)
	dupFD = real
	if _, _, err := s.Call(context.Background(), Frame{Op: "work", Payload: json.RawMessage(`1`)}, []*os.File{w}, okCheck); err != nil {
		t.Fatal(err)
	}
	if got := s.Stats().Spawns; got != 1 {
		t.Fatalf("spawns = %d, want the healthy worker kept", got)
	}
}

func TestCallLaunchDescriptorExhaustionIsNotAFailure(t *testing.T) {
	for _, errno := range []syscall.Errno{syscall.EMFILE, syscall.ENFILE} {
		t.Run(errno.Error(), func(t *testing.T) {
			s := newTestSupervisor(t, func(context.Context) (Process, error) {
				return nil, fmt.Errorf("workerproc: socketpair: %w", errno)
			}, 5*time.Second)
			for range ConsecutiveFailureLimit + 1 {
				_, _, err := s.Call(context.Background(), Frame{Op: "work"}, nil, okCheck)
				if !errors.Is(err, errno) || errors.Is(err, ErrWorkerFailed) {
					t.Fatalf("Call = %v, want local %v", err, errno)
				}
			}
			if st := s.Stats(); st.ConsecutiveFailures != 0 || st.BreakerOpen {
				t.Fatalf("launch exhaustion counted as worker failure: %+v", st)
			}
		})
	}
}

func TestCallMarksWorkerFailures(t *testing.T) {
	reject := func(Frame, []*os.File) (bool, error) { return false, errors.New("bad reply") }
	for _, tc := range []struct {
		name, mode string
		timeout    time.Duration
		check      Check
	}{
		{name: "error frame", mode: "reply-error", timeout: 5 * time.Second, check: okCheck},
		{name: "reply op", mode: "reply-op", timeout: 5 * time.Second, check: okCheck},
		{name: "check", mode: "echo", timeout: 5 * time.Second, check: reject},
		{name: "child exits", mode: "exit", timeout: 5 * time.Second, check: okCheck},
		{name: "timeout", mode: "hang", timeout: 200 * time.Millisecond, check: okCheck},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newTestSupervisor(t, helperLauncher(t, tc.mode), tc.timeout)
			_, _, err := s.Call(context.Background(), Frame{Op: "work", Payload: json.RawMessage(`1`)}, nil, tc.check)
			if !errors.Is(err, ErrWorkerFailed) {
				t.Fatalf("Call = %v, want ErrWorkerFailed", err)
			}
			if tc.mode == "hang" && (!errors.Is(err, ErrTimeout) || !strings.Contains(err.Error(), "after")) {
				t.Fatalf("timeout lost its class or text: %v", err)
			}
		})
	}

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	for _, tc := range []struct {
		name  string
		setup func(*Supervisor) (context.Context, Frame)
	}{
		{name: "stopped", setup: func(s *Supervisor) (context.Context, Frame) {
			_ = s.Stop()
			return context.Background(), Frame{Op: "work"}
		}},
		{name: "breaker open", setup: func(s *Supervisor) (context.Context, Frame) {
			s.consecutive, s.openedAt = ConsecutiveFailureLimit, time.Now()
			return context.Background(), Frame{Op: "work"}
		}},
		{name: "oversize", setup: func(*Supervisor) (context.Context, Frame) {
			return context.Background(), Frame{Op: "work", Payload: json.RawMessage(`"` + strings.Repeat("x", 2<<20) + `"`)}
		}},
		{name: "canceled", setup: func(*Supervisor) (context.Context, Frame) { return canceled, Frame{Op: "work"} }},
		{name: "launch", setup: nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			launch := helperLauncher(t, "echo")
			if tc.setup == nil {
				launch = func(context.Context) (Process, error) { return nil, errors.New("no binary") }
			}
			s := newTestSupervisor(t, launch, 5*time.Second)
			ctx, req := context.Background(), Frame{Op: "work"}
			if tc.setup != nil {
				ctx, req = tc.setup(s)
			}
			if _, _, err := s.Call(ctx, req, nil, okCheck); err == nil || errors.Is(err, ErrWorkerFailed) {
				t.Fatalf("Call = %v, want an error that is not a worker failure", err)
			}
		})
	}
}
