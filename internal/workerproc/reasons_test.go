package workerproc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
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
	if got := s2.Stats().Kills; len(got) != 0 {
		t.Fatalf("launch kills = %v", got)
	}
}

func TestFailureHookSkipsInflightCancellation(t *testing.T) {
	var log failureLog
	s := reasonSupervisor(t, helperLauncher(t, "echo"), 5*time.Second, &log)
	entered, release := installHeldReply(t, s)
	defer release()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, _, err := s.Call(ctx, Frame{Op: "work"}, nil, okCheck)
		done <- err
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("RPC did not start")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) || errors.Is(err, ErrWorkerFailed) || FailureReason(err) != "" {
			t.Fatalf("canceled RPC: %v, reason %q", err, FailureReason(err))
		}
	case <-time.After(time.Second):
		t.Fatal("RPC did not return after cancellation")
	}
	if got := log.got(); len(got) != 0 {
		t.Fatalf("hook called for %q", got)
	}
	if st := s.Stats(); len(st.Kills) != 0 || st.ConsecutiveFailures != 0 {
		t.Fatalf("cancellation counted as failure: %+v", st)
	}
	release()
	waitWorkerQueueIdle(t, s, 0)
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
	if err.Error() != "worker did not start: no bus" {
		t.Fatalf("spawn error text changed: %v", err)
	}
	stats := s.Stats()
	if len(stats.Kills) != 1 || stats.Kills[ReasonSpawn] != 1 {
		t.Fatalf("spawn kills = %v", stats.Kills)
	}
	stats.Kills[ReasonSpawn]++
	if got := s.Stats().Kills[ReasonSpawn]; got != 1 {
		t.Fatalf("snapshot changed supervisor's kills to %d", got)
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
	for _, errno := range []syscall.Errno{syscall.EMFILE, syscall.ENFILE} {
		t.Run(errno.Error(), func(t *testing.T) {
			conn, _ := socketPair(t)
			killed, finished := make(chan struct{}), make(chan struct{})
			reads := 0
			p := &unitProcess{
				unit: "u", conn: conn, done: make(chan struct{}), limit: 1 << 20,
				cg: memoryCgroup{dir: t.TempDir(), v2: true},
				usage: func() (uint64, error) {
					reads++
					if reads <= 3 {
						return 0, fmt.Errorf("read memory: %w", errno)
					}
					return 2 << 20, nil
				},
				killUnit: func(context.Context, *unitProcess) error {
					close(killed)
					return nil
				},
			}
			defer close(p.done)
			go func() {
				defer close(finished)
				p.watch(time.Millisecond)
			}()
			select {
			case <-finished:
			case <-time.After(time.Second):
				t.Fatal("watchdog did not kill after memory exceeded the cap")
			}
			if reads != 4 {
				t.Fatalf("watchdog stopped after %d reads, want three skipped ticks and a memory kill", reads)
			}
			select {
			case <-killed:
			case <-time.After(time.Second):
				t.Fatal("watchdog did not ask systemd to kill the unit")
			}
			if err := p.Kill(); err != nil {
				t.Fatal(err)
			}
			if !p.OOMKilled() {
				t.Fatal("watchdog memory kill lost after a repeated kill without cgroup evidence")
			}
		})
	}
}

// A worker being stopped on purpose loses its cgroup before systemd-run
// exits. The watchdog must not read that gap as a fault and log a kill of a
// worker that is already going.
func TestUnitWatchdogQuietAfterRequestedKill(t *testing.T) {
	conn, _ := socketPair(t)
	var mu sync.Mutex
	var lines []string
	finished := make(chan struct{})
	p := &unitProcess{
		unit: "u", conn: conn, done: make(chan struct{}), limit: 1 << 20,
		cg: memoryCgroup{dir: t.TempDir(), v2: true},
		usage: func() (uint64, error) {
			return 0, fmt.Errorf("read memory: %w", os.ErrNotExist)
		},
		killUnit: func(context.Context, *unitProcess) error { return nil },
		log: func(format string, args ...any) {
			mu.Lock()
			defer mu.Unlock()
			lines = append(lines, fmt.Sprintf(format, args...))
		},
	}
	defer close(p.done)
	if err := p.Kill(); err != nil {
		t.Fatal(err)
	}
	go func() {
		defer close(finished)
		p.watch(time.Millisecond)
	}()
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("watchdog kept polling a worker already being killed")
	}
	mu.Lock()
	defer mu.Unlock()
	if len(lines) != 0 {
		t.Fatalf("watchdog logged %q for a worker already being killed", lines)
	}
}

// A deliberate kill can remove the cgroup while a watchdog read is already
// in flight. That read must not relabel the stop as a memory fault.
func TestUnitWatchdogKillDuringMemoryRead(t *testing.T) {
	for _, tc := range []struct {
		name string
		used uint64
		err  error
	}{
		{name: "cgroup removed", err: fmt.Errorf("read memory: %w", os.ErrNotExist)},
		{name: "over cap", used: 2 << 20},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conn, _ := socketPair(t)
			reading, release := make(chan struct{}), make(chan struct{})
			releaseRead := sync.OnceFunc(func() { close(release) })
			defer releaseRead()
			finished, killed := make(chan struct{}), make(chan struct{})
			var kills atomic.Int32
			var mu sync.Mutex
			var lines []string
			p := &unitProcess{
				unit: "u", conn: conn, done: make(chan struct{}), limit: 1 << 20,
				cg: memoryCgroup{dir: t.TempDir(), v2: true},
				usage: func() (uint64, error) {
					close(reading)
					<-release
					return tc.used, tc.err
				},
				killUnit: func(context.Context, *unitProcess) error {
					if kills.Add(1) == 1 {
						close(killed)
					}
					return nil
				},
				log: func(format string, args ...any) {
					mu.Lock()
					defer mu.Unlock()
					lines = append(lines, fmt.Sprintf(format, args...))
				},
			}
			defer close(p.done)
			go func() {
				defer close(finished)
				p.watch(time.Millisecond)
			}()
			select {
			case <-reading:
			case <-time.After(time.Second):
				t.Fatal("watchdog did not read memory")
			}
			if err := p.Kill(); err != nil {
				t.Fatal(err)
			}
			select {
			case <-killed:
			case <-time.After(time.Second):
				t.Fatal("kill was not sent while the memory read was pending")
			}
			releaseRead()
			select {
			case <-finished:
			case <-time.After(time.Second):
				t.Fatal("watchdog kept running after the requested kill")
			}
			if p.OOMKilled() {
				t.Error("deliberate kill reported as an OOM kill")
			}
			if got := kills.Load(); got != 1 {
				t.Errorf("unit killed %d times, want once", got)
			}
			mu.Lock()
			defer mu.Unlock()
			if len(lines) != 0 {
				t.Errorf("watchdog logged %q after a deliberate kill", lines)
			}
		})
	}
}

// Kernel OOM evidence can arrive after a requested kill ends memory polling.
// That polling shutdown must leave the independent kernel verdict available.
func TestUnitKillKeepsKernelOOMVerdict(t *testing.T) {
	for _, version := range []string{"v1", "v2"} {
		t.Run(version, func(t *testing.T) {
			conn, _ := socketPair(t)
			p := &unitProcess{
				unit: "u", conn: conn, done: make(chan struct{}),
				cg: memoryCgroup{dir: t.TempDir(), v2: version == "v2"},
				usage: func() (uint64, error) {
					t.Error("watchdog read memory after a requested kill")
					return 0, os.ErrNotExist
				},
				killUnit: func(context.Context, *unitProcess) error { return nil },
			}
			defer close(p.done)
			if version == "v1" {
				p.oom = &oomWatch{done: make(chan struct{})}
			} else {
				p.slice = &memoryCgroup{dir: t.TempDir(), v2: true}
				p.sliceOOMKills = 2
				writeValue(t, filepath.Join(p.slice.dir, "memory.events"), "oom_kill 2\n")
			}
			if err := p.Kill(); err != nil {
				t.Fatal(err)
			}
			finished := make(chan struct{})
			go func() {
				defer close(finished)
				p.watch(time.Millisecond)
			}()
			select {
			case <-finished:
			case <-time.After(time.Second):
				t.Fatal("watchdog kept running after a requested kill")
			}
			if version == "v1" {
				p.oom.seen.Store(true)
				close(p.oom.done)
			} else {
				writeValue(t, filepath.Join(p.slice.dir, "memory.events"), "oom_kill 3\n")
			}
			if !p.OOMKilled() {
				t.Fatal("kernel OOM verdict lost after the watchdog stopped")
			}
		})
	}
}
