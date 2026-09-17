package yaraworker

import (
	"context"
	"os"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// ScanBytesChecked is the fail-closed entrypoint: before Start (no worker) it
// must return an error, not nil, so a caller does not read "no matches" as
// "clean file".
func TestSupervisorScanBytesCheckedBeforeStartErrors(t *testing.T) {
	sup, err := NewSupervisor(SupervisorConfig{BinaryPath: "/usr/bin/true", SocketPath: "/tmp/unused.sock"})
	if err != nil {
		t.Fatalf("NewSupervisor: %v", err)
	}
	if _, err := sup.ScanBytesChecked([]byte("x")); err == nil {
		t.Fatal("ScanBytesChecked before Start must fail closed with an error")
	}
}

// The crash finding describes the outage at exit. Scans can resume before
// OnStable restores worker health, so that health delay is not scan downtime.
func TestSupervisorScanAvailabilityAcrossRestart(t *testing.T) {
	crashed := make(chan struct{})
	var stable atomic.Bool
	sup, err := NewSupervisor(SupervisorConfig{
		BinaryPath:         os.Args[0],
		SocketPath:         shortSockPath(t),
		StartTimeout:       3 * time.Second,
		MinRestartInterval: 20 * time.Millisecond,
		StableDuration:     time.Hour,
		ClientTimeout:      2 * time.Second,
		Env:                helperEnv("normal"),
		OnStable:           func() { stable.Store(true) },
	})
	if err != nil {
		t.Fatal(err)
	}
	sup.cfg.OnRestart = func(int, syscall.Signal, time.Duration) {
		if pid := sup.ChildPID(); pid != 0 {
			t.Errorf("crash callback still reports child %d", pid)
		}
		if _, scanErr := sup.ScanBytesChecked([]byte("payload")); scanErr == nil {
			t.Error("byte scan succeeded during the crash callback")
		}
		if _, scanErr := sup.ScanFileChecked("/unused", 1024); scanErr == nil {
			t.Error("file scan succeeded during the crash callback")
		}
		close(crashed)
	}
	if err = sup.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sup.Stop() }()
	child, err := os.FindProcess(sup.ChildPID())
	if err != nil {
		t.Fatal(err)
	}
	if err := child.Kill(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-crashed:
	case <-time.After(5 * time.Second):
		t.Fatal("worker crash was not reported")
	}
	waitFor(t, "scanning after restart", func() bool {
		_, err := sup.ScanBytesChecked([]byte("payload"))
		return err == nil
	})
	if _, err := sup.ScanFileChecked("/unused", 1024); err != nil {
		t.Fatalf("file scan after restart: %v", err)
	}
	if stable.Load() {
		t.Fatal("worker reported stable before scan availability was checked")
	}
}

// On a healthy worker a checked scan of a clean payload returns no matches and
// a nil error (distinct from the error case above).
func TestSupervisorScanBytesCheckedHealthyWorker(t *testing.T) {
	sock := shortSockPath(t)
	cfg := SupervisorConfig{
		BinaryPath:         os.Args[0],
		SocketPath:         sock,
		StartTimeout:       3 * time.Second,
		MinRestartInterval: 50 * time.Millisecond,
		MaxRestartInterval: 500 * time.Millisecond,
		StableDuration:     50 * time.Millisecond,
		ClientTimeout:      2 * time.Second,
		Env:                helperEnv("normal"),
	}
	sup, err := NewSupervisor(cfg)
	if err != nil {
		t.Fatalf("NewSupervisor: %v", err)
	}
	if err = sup.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() { _ = sup.Stop() }()

	m, err := sup.ScanBytesChecked([]byte("payload"))
	if err != nil {
		t.Fatalf("ScanBytesChecked on healthy worker: %v", err)
	}
	if m != nil {
		t.Errorf("scripted worker returns no matches, got %v", m)
	}
}
