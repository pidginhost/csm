package yaraworker

import (
	"context"
	"os"
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
