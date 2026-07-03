package yaraworker

import (
	"context"
	"os"
	"testing"
	"time"
)

// A worker that is alive but whose rules failed to compile must report the
// compile error to the supervisor, so the daemon can raise a finding instead
// of the dead backend looking like an innocuous "0 rules" host.
func TestSupervisorCompileErrorSurfaced(t *testing.T) {
	sock := shortSockPath(t)
	cfg := SupervisorConfig{
		BinaryPath:         os.Args[0],
		SocketPath:         sock,
		StartTimeout:       3 * time.Second,
		MinRestartInterval: 50 * time.Millisecond,
		MaxRestartInterval: 500 * time.Millisecond,
		StableDuration:     50 * time.Millisecond,
		ClientTimeout:      2 * time.Second,
		Env:                helperEnv("normal", "YARAWORKER_RULE_COUNT=0", "YARAWORKER_COMPILE_ERR=bad rule at line 7"),
	}
	sup, err := NewSupervisor(cfg)
	if err != nil {
		t.Fatalf("NewSupervisor: %v", err)
	}
	if err = sup.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() { _ = sup.Stop() }()

	if got := sup.CompileError(); got != "bad rule at line 7" {
		t.Errorf("CompileError() = %q, want the worker's compile error", got)
	}
}

// A healthy worker reports no compile error.
func TestSupervisorCompileErrorEmptyWhenHealthy(t *testing.T) {
	sock := shortSockPath(t)
	cfg := SupervisorConfig{
		BinaryPath:         os.Args[0],
		SocketPath:         sock,
		StartTimeout:       3 * time.Second,
		MinRestartInterval: 50 * time.Millisecond,
		MaxRestartInterval: 500 * time.Millisecond,
		StableDuration:     50 * time.Millisecond,
		ClientTimeout:      2 * time.Second,
		Env:                helperEnv("normal", "YARAWORKER_RULE_COUNT=7"),
	}
	sup, err := NewSupervisor(cfg)
	if err != nil {
		t.Fatalf("NewSupervisor: %v", err)
	}
	if err = sup.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() { _ = sup.Stop() }()

	if got := sup.CompileError(); got != "" {
		t.Errorf("CompileError() = %q, want empty for a healthy worker", got)
	}
	// Before start there is no worker to ask: also empty, not a crash.
}
