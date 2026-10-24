package workerproc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"
)

type failureLog struct {
	mu      sync.Mutex
	reasons []string
}

func (l *failureLog) hook(reason string, _ error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.reasons = append(l.reasons, reason)
}

func (l *failureLog) got() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.reasons...)
}

func reasonSupervisor(t *testing.T, launch Launcher, timeout time.Duration, log *failureLog) *Supervisor {
	t.Helper()
	s, err := New(Config{Name: "test worker", Launch: launch, Timeout: timeout, Limits: Limits{MaxFrameBytes: 1 << 20, MaxFDs: 4}, OnFailure: log.hook})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Stop() })
	return s
}

func TestCallReportsFailureReasons(t *testing.T) {
	reject := func(Frame, []*os.File) (bool, error) { return false, errors.New("bad reply") }
	for _, tc := range []struct {
		mode, want string
		timeout    time.Duration
		check      Check
	}{
		{"hang", ReasonTimeout, 200 * time.Millisecond, okCheck},
		{"reply-error", ReasonProtocol, 5 * time.Second, okCheck},
		{"reply-op", ReasonProtocol, 5 * time.Second, okCheck},
		{"echo", ReasonProtocol, 5 * time.Second, reject},
		{"exit", ReasonCrash, 5 * time.Second, okCheck},
	} {
		t.Run(tc.mode+"/"+tc.want, func(t *testing.T) {
			var log failureLog
			s := reasonSupervisor(t, helperLauncher(t, tc.mode), tc.timeout, &log)
			_, _, err := s.Call(context.Background(), Frame{Op: "work", Payload: json.RawMessage(`1`)}, nil, tc.check)
			if got := FailureReason(err); got != tc.want {
				t.Fatalf("FailureReason(%v) = %q, want %q", err, got, tc.want)
			}
			if got := log.got(); len(got) != 1 || got[0] != tc.want {
				t.Fatalf("hook saw %q", got)
			}
			if got := s.Stats().Kills[tc.want]; got != 1 {
				t.Fatalf("Kills[%s] = %d", tc.want, got)
			}
		})
	}
}

// oomProcess reports an OOM kill, as a unit's cgroup would.
type oomProcess struct{ Process }

func (oomProcess) OOMKilled() bool { return true }

func TestCallReportsOOMFromProcess(t *testing.T) {
	inner := helperLauncher(t, "exit")
	var log failureLog
	s := reasonSupervisor(t, func(ctx context.Context) (Process, error) {
		p, err := inner(ctx)
		if err != nil {
			return nil, err
		}
		return oomProcess{p}, nil
	}, 5*time.Second, &log)
	_, _, err := s.Call(context.Background(), Frame{Op: "work"}, nil, okCheck)
	if got := FailureReason(err); got != ReasonOOM || !errors.Is(err, ErrWorkerFailed) {
		t.Fatalf("FailureReason(%v) = %q, want oom", err, got)
	}
}

func TestFailureHookSkipsCancellationAndExhaustion(t *testing.T) {
	var log failureLog
	s := reasonSupervisor(t, pairLauncher(t, echoPayload), 5*time.Second, &log)
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := s.Call(canceled, Frame{Op: "work"}, nil, okCheck); FailureReason(err) != "" {
		t.Fatalf("canceled call reason %q", FailureReason(err))
	}
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	real := dupFD
	dupFD = func(int) (int, error) { return -1, syscall.EMFILE }
	_, _, err = s.Call(context.Background(), Frame{Op: "work"}, []*os.File{w}, okCheck)
	dupFD = real
	if FailureReason(err) != "" {
		t.Fatalf("descriptor exhaustion reason %q", FailureReason(err))
	}
	s2 := reasonSupervisor(t, func(context.Context) (Process, error) {
		return nil, fmt.Errorf("socketpair: %w", syscall.ENFILE)
	}, 5*time.Second, &log)
	if _, _, err := s2.Call(context.Background(), Frame{Op: "work"}, nil, okCheck); FailureReason(err) != "" {
		t.Fatalf("launch exhaustion reason %q", FailureReason(err))
	}
	if got := log.got(); len(got) != 0 {
		t.Fatalf("hook called for %q", got)
	}
	if got := s.Stats().Kills; len(got) != 0 {
		t.Fatalf("kills = %v", got)
	}
}

func TestCallLaunchFailureReasonSpawn(t *testing.T) {
	var log failureLog
	s := reasonSupervisor(t, func(context.Context) (Process, error) { return nil, errors.New("no bus") }, 5*time.Second, &log)
	_, _, err := s.Call(context.Background(), Frame{Op: "work"}, nil, okCheck)
	if FailureReason(err) != ReasonSpawn || errors.Is(err, ErrWorkerFailed) || !errors.Is(err, ErrSpawn) {
		t.Fatalf("launch failure: reason %q err %v", FailureReason(err), err)
	}
	if got := log.got(); len(got) != 1 || got[0] != ReasonSpawn {
		t.Fatalf("hook saw %q", got)
	}
}

func TestUnitOOMKilledReadsCgroupEvents(t *testing.T) {
	for _, tc := range []struct {
		v2         bool
		file, body string
		want       bool
	}{
		{true, "memory.events", "low 0\nhigh 0\nmax 4\noom 1\noom_kill 1\n", true},
		{true, "memory.events", "low 0\nhigh 0\nmax 0\noom 0\noom_kill 0\n", false},
		{false, "memory.oom_control", "oom_kill_disable 0\nunder_oom 0\noom_kill 2\n", true},
	} {
		dir := t.TempDir()
		writeValue(t, filepath.Join(dir, tc.file), tc.body)
		p := &unitProcess{cg: memoryCgroup{dir: dir, v2: tc.v2}}
		if got := p.OOMKilled(); got != tc.want {
			t.Errorf("%s %q: OOMKilled = %v", tc.file, tc.body, got)
		}
	}
	if (&unitProcess{cg: memoryCgroup{dir: filepath.Join(t.TempDir(), "gone"), v2: true}}).OOMKilled() {
		t.Error("missing cgroup read as an OOM kill")
	}
}

func TestUnitWatchdogSkipsDaemonExhaustion(t *testing.T) {
	var kills int
	var mu sync.Mutex
	p := &unitProcess{
		unit:  "u",
		done:  make(chan struct{}),
		limit: 1 << 20,
		usage: func() (uint64, error) { return 0, syscall.EMFILE },
		killUnit: func(context.Context, *unitProcess) error {
			mu.Lock()
			kills++
			mu.Unlock()
			return nil
		},
	}
	go p.watch(5 * time.Millisecond)
	time.Sleep(60 * time.Millisecond)
	close(p.done)
	mu.Lock()
	defer mu.Unlock()
	if kills != 0 {
		t.Fatalf("watchdog killed a worker over the daemon's own descriptor exhaustion")
	}
}
