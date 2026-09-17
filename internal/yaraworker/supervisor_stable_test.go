package yaraworker

import (
	"context"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// A restart that reaches readiness is not proof the worker recovered: one that
// dies seconds later keeps scanning offline. OnStable reports only a worker
// that stayed up for StableDuration.
func TestSupervisorReportsStableWorker(t *testing.T) {
	sock := shortSockPath(t)
	var stable, restarts atomic.Int32
	sup, err := NewSupervisor(SupervisorConfig{
		BinaryPath:         os.Args[0],
		SocketPath:         sock,
		StartTimeout:       3 * time.Second,
		MinRestartInterval: 20 * time.Millisecond,
		MaxRestartInterval: 50 * time.Millisecond,
		StableDuration:     150 * time.Millisecond,
		ClientTimeout:      2 * time.Second,
		Env:                helperEnv("normal"),
		OnRestart:          func(int, syscall.Signal, time.Duration) { restarts.Add(1) },
		OnStable:           func() { stable.Add(1) },
	})
	if err != nil {
		t.Fatalf("NewSupervisor: %v", err)
	}
	if err := sup.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() { _ = sup.Stop() }()

	waitFor(t, "stable report for the first worker", func() bool { return stable.Load() == 1 })

	if err := sup.RestartWorker(); err != nil {
		t.Fatalf("RestartWorker: %v", err)
	}
	waitFor(t, "stable report for the restarted worker", func() bool { return restarts.Load() == 1 && stable.Load() == 2 })
}

func TestSupervisorDoesNotReportStableWhileCrashLooping(t *testing.T) {
	sock := shortSockPath(t)
	var stable, restarts atomic.Int32
	sup, err := NewSupervisor(SupervisorConfig{
		BinaryPath:         os.Args[0],
		SocketPath:         sock,
		StartTimeout:       3 * time.Second,
		MinRestartInterval: 20 * time.Millisecond,
		MaxRestartInterval: 50 * time.Millisecond,
		StableDuration:     400 * time.Millisecond,
		ClientTimeout:      2 * time.Second,
		Env:                helperEnv("crash-after-delay", "YARAWORKER_EXIT_AFTER=100ms"),
		OnRestart:          func(int, syscall.Signal, time.Duration) { restarts.Add(1) },
		OnStable:           func() { stable.Add(1) },
	})
	if err != nil {
		t.Fatalf("NewSupervisor: %v", err)
	}
	if err := sup.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() { _ = sup.Stop() }()

	// Observe well past StableDuration so a stale timer from any earlier
	// worker has had the chance to fire.
	began := time.Now()
	waitFor(t, "repeated crashes over several stable windows", func() bool {
		return restarts.Load() >= 3 && time.Since(began) >= 3*400*time.Millisecond
	})
	if got := stable.Load(); got != 0 {
		t.Fatalf("crash-looping worker reported stable %d times", got)
	}
}

func TestSupervisorDoesNotReportStableAfterStop(t *testing.T) {
	sock := shortSockPath(t)
	var stable atomic.Int32
	sup, err := NewSupervisor(SupervisorConfig{
		BinaryPath:     os.Args[0],
		SocketPath:     sock,
		StartTimeout:   3 * time.Second,
		StableDuration: 150 * time.Millisecond,
		ClientTimeout:  2 * time.Second,
		Env:            helperEnv("normal"),
		OnStable:       func() { stable.Add(1) },
	})
	if err != nil {
		t.Fatalf("NewSupervisor: %v", err)
	}
	if err := sup.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if err := sup.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	time.Sleep(300 * time.Millisecond)
	if got := stable.Load(); got != 0 {
		t.Fatalf("stopped supervisor reported stable %d times", got)
	}
}

func TestSupervisorStopWaitsForStableCallback(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	finished := make(chan struct{})
	sup, err := NewSupervisor(SupervisorConfig{
		BinaryPath:     os.Args[0],
		SocketPath:     shortSockPath(t),
		StartTimeout:   3 * time.Second,
		StableDuration: 20 * time.Millisecond,
		ClientTimeout:  2 * time.Second,
		Env:            helperEnv("normal"),
		OnStable: func() {
			close(entered)
			<-release
			close(finished)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	// Release before stopping even when an assertion fails.
	defer func() { _ = sup.Stop() }()
	defer close(release)
	if startErr := sup.Start(context.Background()); startErr != nil {
		t.Fatal(startErr)
	}
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("stable callback did not start")
	}
	stopped := make(chan error, 1)
	go func() { stopped <- sup.Stop() }()
	select {
	case <-sup.done:
	case <-time.After(5 * time.Second):
		t.Fatal("supervisor did not stop its worker")
	}
	select {
	case err := <-stopped:
		t.Fatalf("Stop returned before the stable callback finished: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	// The deferred release lets the callback finish; wait for Stop in cleanup.
	t.Cleanup(func() {
		select {
		case err := <-stopped:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("Stop did not finish after the callback was released")
		}
		select {
		case <-finished:
		default:
			t.Fatal("Stop returned while the stable callback was still running")
		}
	})
}

// If a crash wins the child-state race while a recovery callback is already
// running, the crash report must still be the last published health state.
func TestSupervisorCrashReportFollowsInFlightStableCallback(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	var releaseOnce sync.Once
	releaseStable := func() {
		releaseOnce.Do(func() { close(release) })
	}
	events := make(chan string, 2)
	sup, err := NewSupervisor(SupervisorConfig{
		BinaryPath:         os.Args[0],
		SocketPath:         shortSockPath(t),
		StartTimeout:       3 * time.Second,
		MinRestartInterval: time.Hour,
		StableDuration:     20 * time.Millisecond,
		ClientTimeout:      2 * time.Second,
		Env:                helperEnv("normal"),
		OnStable: func() {
			close(entered)
			<-release
			events <- "stable"
		},
		OnRestart: func(int, syscall.Signal, time.Duration) { events <- "crashed" },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sup.Stop() }()
	defer releaseStable()
	if startErr := sup.Start(context.Background()); startErr != nil {
		t.Fatal(startErr)
	}
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("stable callback did not start")
	}
	child, err := os.FindProcess(sup.ChildPID())
	if err != nil {
		t.Fatal(err)
	}
	if err := child.Kill(); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "worker exit", func() bool { return sup.ChildPID() == 0 })
	releaseStable()
	for _, want := range []string{"stable", "crashed"} {
		select {
		case got := <-events:
			if got != want {
				t.Fatalf("callback order: got %s, want %s", got, want)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("missing %s callback", want)
		}
	}
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}
