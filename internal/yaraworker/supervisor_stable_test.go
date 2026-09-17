package yaraworker

import (
	"context"
	"os"
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
