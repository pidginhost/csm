package phptaintworker

import (
	"context"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/phptaint"
)

// helperChild lets a test stand in for the real `csm phptaint-worker`. Mode
// picks the behaviour: a normal worker, one that hangs forever on the first
// request, or one that exits immediately.
func helperChild(t *testing.T, mode string) SupervisorConfig {
	t.Helper()
	return SupervisorConfig{
		Command: os.Args[0],
		Args:    []string{"-test.run=TestHelperWorkerProcess", "--"},
		Env:     append(os.Environ(), "CSM_HELPER_WORKER="+mode),
		Timeout: 2 * time.Second,
	}
}

// TestHelperWorkerProcess is not a real test. It is the child process the
// supervisor tests spawn.
func TestHelperWorkerProcess(t *testing.T) {
	mode := os.Getenv("CSM_HELPER_WORKER")
	if mode == "" {
		t.Skip("not a helper invocation")
	}
	switch mode {
	case "hang":
		// Spin without ever answering. This is what a parser loop looks like
		// from the outside: alive, burning a core, never replying. It must not
		// be reachable by SIGTERM either, which is why the handler is ignored.
		signalIgnore(syscall.SIGTERM)
		// Spinning at 100% CPU is exactly the condition under test: a parser
		// loop that neither returns nor responds to a catchable signal. A
		// sleeping stand-in would be stopped by things that cannot stop the
		// real thing, so the test would pass without proving containment.
		//nolint:staticcheck // SA5002: the busy loop is the fixture, not an oversight.
		for {
		}
	case "exit":
		os.Exit(3)
	default:
		_ = Serve(context.Background(), os.Stdin, os.Stdout)
	}
}

// TestSupervisorKillsAndReapsAHungWorker is the reason this package exists. A
// deadline alone is not containment: the request returns, but the child keeps
// spinning on a core forever, and the next request spawns another one. The
// supervisor must kill the exact process, reap it, and report a coverage gap.
func TestSupervisorKillsAndReapsAHungWorker(t *testing.T) {
	s, err := NewSupervisor(helperChild(t, "hang"))
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	defer func() { _ = s.Stop() }()

	rep := s.Analyze(context.Background(), []byte("<?php eval(curl_exec($c));"))
	if rep.Status != phptaint.StatusTimeout {
		t.Fatalf("status = %v (%s), want StatusTimeout", rep.Status, rep.Reason)
	}
	if rep.Reason == "" {
		t.Fatal("timeout reported with no reason; a gap must say why")
	}
	if len(rep.Results) != 0 {
		t.Fatalf("results = %+v, want none from a killed worker", rep.Results)
	}

	pid := s.LastChildPID()
	if pid <= 0 {
		t.Fatal("no child pid recorded")
	}
	// The process must be GONE, not merely disconnected, and reaped so it is
	// not left as a zombie. Signal 0 probes existence without delivering.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if err := syscall.Kill(pid, 0); err != nil {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("pid %d still alive after a timeout; the hang was not contained", pid)
}

// TestSupervisorReplacesAKilledWorker proves the kill is recoverable: one bad
// file must not end analysis for the rest of the scan.
func TestSupervisorReplacesAKilledWorker(t *testing.T) {
	cfg := helperChild(t, "hang")
	s, err := NewSupervisor(cfg)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	defer func() { _ = s.Stop() }()

	first := s.Analyze(context.Background(), []byte("<?php eval(curl_exec($c));"))
	if first.Status != phptaint.StatusTimeout {
		t.Fatalf("first status = %v, want StatusTimeout", first.Status)
	}
	firstPID := s.LastChildPID()

	s.SetMode("ok") // next spawn behaves
	second := s.Analyze(context.Background(), []byte("<?php $p = curl_exec($c); eval($p);"))
	if second.Status != phptaint.StatusAnalyzed {
		t.Fatalf("second status = %v (%s), want StatusAnalyzed after replacement", second.Status, second.Reason)
	}
	if s.LastChildPID() == firstPID {
		t.Fatal("supervisor reused the killed worker's pid; it must never be reused")
	}
}

// TestSupervisorBreakerStopsRespawnStorm bounds the cost of an account full of
// hanging files. Without it, N crafted files cost N deadlines plus N spawns,
// and one account can consume the whole scan budget.
func TestSupervisorBreakerStopsRespawnStorm(t *testing.T) {
	cfg := helperChild(t, "hang")
	cfg.Timeout = 300 * time.Millisecond
	s, err := NewSupervisor(cfg)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	defer func() { _ = s.Stop() }()

	for i := 0; i < ConsecutiveFailureLimit; i++ {
		if got := s.Analyze(context.Background(), []byte("<?php eval(curl_exec($c));")); got.Status != phptaint.StatusTimeout {
			t.Fatalf("request %d status = %v, want StatusTimeout", i, got.Status)
		}
	}
	spawnsBefore := s.SpawnCount()
	next := s.Analyze(context.Background(), []byte("<?php eval(curl_exec($c));"))
	if next.Status != phptaint.StatusWorkerFailure {
		t.Fatalf("status after the breaker opened = %v, want StatusWorkerFailure", next.Status)
	}
	if s.SpawnCount() != spawnsBefore {
		t.Fatal("supervisor spawned another worker with the breaker open")
	}
	if next.Status == phptaint.StatusAnalyzed || next.Status == phptaint.StatusNotCandidate {
		t.Fatal("an open breaker reported a clean result")
	}
}

// TestSupervisorReportsAWorkerThatExits separates a crash from a hang: both are
// coverage gaps, but they are different gaps and an operator should see which.
func TestSupervisorReportsAWorkerThatExits(t *testing.T) {
	s, err := NewSupervisor(helperChild(t, "exit"))
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	defer func() { _ = s.Stop() }()

	rep := s.Analyze(context.Background(), []byte("<?php eval(curl_exec($c));"))
	if rep.Status != phptaint.StatusWorkerFailure {
		t.Fatalf("status = %v (%s), want StatusWorkerFailure", rep.Status, rep.Reason)
	}
}

// TestSupervisorNeverReportsCleanOnFailure is the invariant the whole design
// serves: no failure path may produce a status a caller reads as "nothing here".
func TestSupervisorNeverReportsCleanOnFailure(t *testing.T) {
	for _, mode := range []string{"hang", "exit"} {
		cfg := helperChild(t, mode)
		cfg.Timeout = 300 * time.Millisecond
		s, err := NewSupervisor(cfg)
		if err != nil {
			t.Fatalf("new: %v", err)
		}
		rep := s.Analyze(context.Background(), []byte("<?php eval(curl_exec($c));"))
		_ = s.Stop()
		if rep.Status == phptaint.StatusAnalyzed || rep.Status == phptaint.StatusNotCandidate {
			t.Fatalf("mode %s reported a clean status %v", mode, rep.Status)
		}
	}
}

var _ = exec.Command
