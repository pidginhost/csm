package phptaintworker

import (
	"context"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/phptaint"
	"github.com/pidginhost/csm/internal/phptaintipc"
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
	case "reply-op":
		if _, err := phptaintipc.ReadFrame(os.Stdin); err != nil {
			t.Fatalf("read helper request: %v", err)
		}
		resp, err := phptaintipc.EncodePayload(phptaintipc.OpAnalyze, phptaintipc.AnalyzeResult{
			Report: phptaint.Report{Status: phptaint.StatusNotCandidate},
		})
		if err != nil {
			t.Fatalf("encode helper response: %v", err)
		}
		if err := phptaintipc.WriteFrame(os.Stdout, resp); err != nil {
			t.Fatalf("write helper response: %v", err)
		}
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

// TestSupervisorContainsRealParserHangs is the end-to-end proof. These are not
// synthetic stand-ins: both inputs make the real parser loop forever inside a
// real worker running the real analyzer. Before isolation, either one pinned a
// core for the life of the daemon and no timeout could stop it, because the
// loop never returns to a point where a deadline or a cancelled context is
// checked.
//
// Each must come back as a coverage gap, promptly, with the worker gone.
func TestSupervisorContainsRealParserHangs(t *testing.T) {
	hangs := map[string]string{
		"unterminated heredoc with a variable variable": "<?php eval curl_exec <<<A\n$$b",
		"terminated heredoc with a variable variable":   "<?php eval curl_exec <<<A\n$$b\nA;",
		"input ending in a less-than":                   "<?php eval(curl_exec($c)); ?><",
	}
	for name, src := range hangs {
		t.Run(name, func(t *testing.T) {
			cfg := helperChild(t, "ok") // a REAL worker running the REAL analyzer
			cfg.Timeout = 3 * time.Second
			s, err := NewSupervisor(cfg)
			if err != nil {
				t.Fatalf("new: %v", err)
			}
			defer func() { _ = s.Stop() }()

			start := time.Now()
			rep := s.Analyze(context.Background(), []byte(src))
			elapsed := time.Since(start)

			if rep.Status != phptaint.StatusTimeout {
				t.Fatalf("status = %v (%s), want StatusTimeout", rep.Status, rep.Reason)
			}
			if elapsed > 30*time.Second {
				t.Fatalf("took %s to contain a hang; the deadline did not bound it", elapsed)
			}
			pid := s.LastChildPID()
			deadline := time.Now().Add(5 * time.Second)
			for time.Now().Before(deadline) {
				if err := syscall.Kill(pid, 0); err != nil {
					return
				}
				time.Sleep(20 * time.Millisecond)
			}
			t.Fatalf("worker %d survived a real parser hang", pid)
		})
	}
}

func TestSupervisorBoundsAWriteToAnUnresponsiveWorker(t *testing.T) {
	cfg := helperChild(t, "hang")
	cfg.Timeout = 300 * time.Millisecond
	s, err := NewSupervisor(cfg)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	defer func() { _ = s.Stop() }()

	start := time.Now()
	rep := s.Analyze(context.Background(), make([]byte, phptaint.MaxSourceBytes))
	if rep.Status != phptaint.StatusTimeout {
		t.Fatalf("status = %v (%s), want StatusTimeout", rep.Status, rep.Reason)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("blocked pipe write escaped the request deadline: %s", elapsed)
	}
	if pid := s.LastChildPID(); pid <= 0 {
		t.Fatal("no worker was started")
	} else if err := syscall.Kill(pid, 0); err == nil {
		t.Fatalf("worker %d survived a timed-out pipe write", pid)
	}
}

func TestSupervisorDoesNotStartForCanceledContext(t *testing.T) {
	s, err := NewSupervisor(helperChild(t, "ok"))
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	defer func() { _ = s.Stop() }()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	rep := s.Analyze(ctx, []byte("<?php eval(curl_exec($c));"))
	if rep.Status != phptaint.StatusCanceled {
		t.Fatalf("status = %v (%s), want StatusCanceled", rep.Status, rep.Reason)
	}
	if s.SpawnCount() != 0 {
		t.Fatalf("spawn count = %d, want 0 for an already-canceled request", s.SpawnCount())
	}
}

func TestSupervisorCanceledRequestsDoNotOpenBreaker(t *testing.T) {
	cfg := helperChild(t, "hang")
	cfg.Timeout = 2 * time.Second
	s, err := NewSupervisor(cfg)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	defer func() { _ = s.Stop() }()

	for i := 0; i < ConsecutiveFailureLimit; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		rep := s.Analyze(ctx, []byte("<?php eval(curl_exec($c));"))
		cancel()
		if rep.Status != phptaint.StatusCanceled {
			t.Fatalf("request %d status = %v (%s), want StatusCanceled", i, rep.Status, rep.Reason)
		}
	}
	s.SetMode("ok")
	rep := s.Analyze(context.Background(), []byte("<?php $p = curl_exec($c); eval($p);"))
	if rep.Status != phptaint.StatusAnalyzed {
		t.Fatalf("status after caller cancellations = %v (%s), want StatusAnalyzed", rep.Status, rep.Reason)
	}
}

func TestSupervisorRejectsResponseWithAnOp(t *testing.T) {
	s, err := NewSupervisor(helperChild(t, "reply-op"))
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	defer func() { _ = s.Stop() }()

	rep := s.Analyze(context.Background(), []byte("<?php eval(curl_exec($c));"))
	if rep.Status != phptaint.StatusWorkerFailure {
		t.Fatalf("status = %v (%s), want StatusWorkerFailure", rep.Status, rep.Reason)
	}
	if !strings.Contains(rep.Reason, "response carries op") {
		t.Fatalf("reason = %q, want response-op protocol error", rep.Reason)
	}
}

// TestRealHangIsStillUnstoppableInProcess documents why the process boundary is
// not optional. If this ever stops timing out, the parser was fixed and the
// isolation could in principle be revisited -- but not before.
func TestRealHangIsStillUnstoppableInProcess(t *testing.T) {
	if testing.Short() {
		t.Skip("spins a core for the duration")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		// Deliberately in-process: a cancelled context does NOT stop this.
		_ = phptaint.Analyze(ctx, []byte("<?php eval curl_exec <<<A\n$$b"))
	}()
	select {
	case <-done:
		t.Fatal("the parser hang is gone; revisit whether isolation is still required")
	case <-time.After(5 * time.Second):
		// Expected: still spinning. The goroutine is abandoned, which is
		// precisely the leak a separate process converts into a killable one.
	}
}

// TestSupervisorBreakerRecoversAfterCooldown is the difference between a
// circuit breaker and a kill switch. Without a way back, a tenant on a shared
// host disables PHP analysis for every account on that host, permanently, with
// a handful of crafted files -- and an operator still believes the detector is
// running. The breaker must bound the storm and then let the host recover on
// its own.
func TestSupervisorBreakerRecoversAfterCooldown(t *testing.T) {
	cfg := helperChild(t, "hang")
	cfg.Timeout = 200 * time.Millisecond
	s, err := NewSupervisor(cfg)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	defer func() { _ = s.Stop() }()

	clock := time.Now()
	s.now = func() time.Time { return clock }

	for i := 0; i < ConsecutiveFailureLimit; i++ {
		if got := s.Analyze(context.Background(), []byte("<?php eval(curl_exec($c));")); got.Status != phptaint.StatusTimeout {
			t.Fatalf("request %d status = %v, want StatusTimeout", i, got.Status)
		}
	}

	// Still inside the cooldown: refused without spawning.
	spawns := s.SpawnCount()
	if got := s.Analyze(context.Background(), []byte("<?php eval(curl_exec($c));")); got.Status != phptaint.StatusWorkerFailure {
		t.Fatalf("status during cooldown = %v, want StatusWorkerFailure", got.Status)
	}
	if s.SpawnCount() != spawns {
		t.Fatal("spawned a worker while the breaker was open")
	}

	// Past the cooldown, with a healthy worker, the host recovers.
	clock = clock.Add(breakerCooldown + time.Second)
	s.SetMode("ok")
	got := s.Analyze(context.Background(), []byte("<?php $p = curl_exec($c); eval($p);"))
	if got.Status != phptaint.StatusAnalyzed {
		t.Fatalf("status after cooldown = %v (%s), want StatusAnalyzed", got.Status, got.Reason)
	}

	// And the counter is genuinely reset, not merely bypassed once.
	for i := 0; i < ConsecutiveFailureLimit+2; i++ {
		if r := s.Analyze(context.Background(), []byte("<?php $p = curl_exec($c); eval($p);")); r.Status != phptaint.StatusAnalyzed {
			t.Fatalf("post-recovery request %d status = %v, want StatusAnalyzed", i, r.Status)
		}
	}
}

// TestSupervisorBreakerRetriesOncePerCooldown pins the storm bound that makes
// recovery affordable: a host that stays broken must cost one trial per
// cooldown, not one per file.
func TestSupervisorBreakerRetriesOncePerCooldown(t *testing.T) {
	cfg := helperChild(t, "hang")
	cfg.Timeout = 200 * time.Millisecond
	s, err := NewSupervisor(cfg)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	defer func() { _ = s.Stop() }()

	clock := time.Now()
	s.now = func() time.Time { return clock }
	for i := 0; i < ConsecutiveFailureLimit; i++ {
		s.Analyze(context.Background(), []byte("<?php eval(curl_exec($c));"))
	}

	spawns := s.SpawnCount()
	for i := 0; i < 25; i++ {
		s.Analyze(context.Background(), []byte("<?php eval(curl_exec($c));"))
	}
	if s.SpawnCount() != spawns {
		t.Fatalf("spawned %d workers during one cooldown, want 0", s.SpawnCount()-spawns)
	}

	clock = clock.Add(breakerCooldown + time.Second)
	s.Analyze(context.Background(), []byte("<?php eval(curl_exec($c));"))
	if s.SpawnCount() != spawns+1 {
		t.Fatalf("spawns after cooldown = %d, want exactly one trial", s.SpawnCount()-spawns)
	}

	// The failed trial restarts the cooldown. More files arriving immediately
	// must not turn the half-open state into an unbounded respawn loop.
	for i := 0; i < 25; i++ {
		s.Analyze(context.Background(), []byte("<?php eval(curl_exec($c));"))
	}
	if s.SpawnCount() != spawns+1 {
		t.Fatalf("spawned %d workers after a failed trial, want 0 until the next cooldown", s.SpawnCount()-(spawns+1))
	}
}
