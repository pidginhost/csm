package phptaintworker

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/phptaint"
	"github.com/pidginhost/csm/internal/phptaintipc"
	"github.com/pidginhost/csm/internal/workerproc"
)

// helperChild lets a test stand in for the real `csm phptaint-worker`. Mode
// picks the behaviour: a normal worker, one that hangs forever on the first
// request, or one that exits immediately.
// workerInput passes the pre-filter, so it reaches the worker. Content the
// pre-filter rejects is answered without one.
const workerInput = "<?php $p = curl_exec($c); eval($p);"

// candidateOfSize pads workerInput to n bytes.
func candidateOfSize(n int) []byte {
	src := bytes.Repeat([]byte(" "), n)
	copy(src, workerInput)
	return src
}

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
	if mode == "exit" {
		os.Exit(3)
	}
	conn, err := workerproc.ChildConn()
	if err != nil {
		t.Fatalf("helper connection: %v", err)
	}
	lim := workerproc.Limits{MaxFrameBytes: phptaintipc.MaxFrameBytes}
	send := func(resp workerproc.Frame) {
		if err := workerproc.SendFrame(conn, resp, nil, lim.MaxFrameBytes); err != nil {
			t.Fatalf("write helper response: %v", err)
		}
	}
	switch {
	case mode == "hang":
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
	case mode == "reply-op":
		if _, _, err := workerproc.ReceiveFrame(conn, lim); err != nil {
			t.Fatalf("read helper request: %v", err)
		}
		resp, err := phptaintipc.EncodePayload(phptaintipc.OpAnalyze, phptaintipc.AnalyzeResult{
			Report: phptaint.Report{Status: phptaint.StatusNotCandidate},
		})
		if err != nil {
			t.Fatalf("encode helper response: %v", err)
		}
		send(resp)
	case mode == "reply-offset-at-len", mode == "reply-offset-direct":
		req, _, err := workerproc.ReceiveFrame(conn, lim)
		if err != nil {
			t.Fatalf("read helper request: %v", err)
		}
		var args phptaintipc.AnalyzeArgs
		if decodeErr := phptaintipc.DecodePayload(req, &args); decodeErr != nil {
			t.Fatalf("decode helper request: %v", decodeErr)
		}
		offset := -1
		if mode == "reply-offset-at-len" {
			// One past the last byte: the smallest offset outside the source.
			offset = len(args.Source)
		}
		resp, err := phptaintipc.EncodePayload("", phptaintipc.AnalyzeResult{
			Report: helperOffsetReport(offset),
		})
		if err != nil {
			t.Fatalf("encode helper response: %v", err)
		}
		send(resp)
	case strings.HasPrefix(mode, "hold:"):
		// Hold the request until the test says so, signalling through files
		// in a directory both processes can see.
		dir := strings.TrimPrefix(mode, "hold:")
		if _, _, err := workerproc.ReceiveFrame(conn, lim); err != nil {
			t.Fatalf("read helper request: %v", err)
		}
		if err := os.WriteFile(filepath.Join(dir, "entered"), nil, 0o600); err != nil {
			t.Fatalf("signal entered: %v", err)
		}
		for {
			if _, err := os.Stat(filepath.Join(dir, "release")); err == nil {
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		resp, err := phptaintipc.EncodePayload("", phptaintipc.AnalyzeResult{
			Report: phptaint.Report{Status: phptaint.StatusNotCandidate},
		})
		if err != nil {
			t.Fatalf("encode helper response: %v", err)
		}
		send(resp)
	default:
		_ = Serve(context.Background(), conn)
	}
}

// helperOffsetReport is a report the source-independent checks accept, so the
// only thing that can reject it is the offset's bound against the source.
func helperOffsetReport(offset int) phptaint.Report {
	return phptaint.Report{
		Status:       phptaint.StatusAnalyzed,
		TotalResults: 1,
		Results: []phptaint.Result{{
			Source:           "curl_exec",
			Sink:             "eval",
			Confidence:       phptaint.ConfidenceHigh,
			Basis:            phptaint.BasisCallArgument,
			ResolutionOffset: offset,
		}},
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
	rep := s.Analyze(context.Background(), candidateOfSize(phptaint.MaxSourceBytes))
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

// A worker that points a resolution offset past the end of the submitted
// source is not trusted: the reply is a worker failure, never evidence.
func TestSupervisorRejectsOffsetOutsideSource(t *testing.T) {
	s, err := NewSupervisor(helperChild(t, "reply-offset-at-len"))
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	defer func() { _ = s.Stop() }()

	rep := s.Analyze(context.Background(), []byte("<?php eval(curl_exec($c));"))
	if rep.Status != phptaint.StatusWorkerFailure {
		t.Fatalf("status = %v (%s), want StatusWorkerFailure", rep.Status, rep.Reason)
	}
	if !strings.Contains(rep.Reason, "resolution offset") {
		t.Fatalf("reason = %q, want resolution-offset protocol error", rep.Reason)
	}
}

func TestSupervisorPassesDirectResultUnchanged(t *testing.T) {
	s, err := NewSupervisor(helperChild(t, "reply-offset-direct"))
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	defer func() { _ = s.Stop() }()

	rep := s.Analyze(context.Background(), []byte("<?php eval(curl_exec($c));"))
	want := helperOffsetReport(-1)
	if rep.Status != want.Status || rep.TotalResults != want.TotalResults || rep.Reason != "" ||
		len(rep.Results) != 1 || rep.Results[0].Basis != want.Results[0].Basis ||
		rep.Results[0].ResolutionOffset != -1 || rep.Results[0].Confidence != want.Results[0].Confidence ||
		rep.Results[0].Source != want.Results[0].Source || rep.Results[0].Sink != want.Results[0].Sink {
		t.Fatalf("report = %+v, want %+v", rep, want)
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

// Content the pre-filter rejects is answered in this process. It never
// starts, queues behind or waits for the worker, and a missing or stopped
// worker is not a gap in its coverage: there was nothing to examine.
func TestSupervisorAnswersNonCandidatesWithoutWorker(t *testing.T) {
	s, err := NewSupervisor(SupervisorConfig{Command: filepath.Join(t.TempDir(), "missing-worker"), Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	nonCandidates := []string{"<?php echo 'safe';", "body { color: red }", "\x89PNG\r\n\x1a\n\x00\x00"}
	for _, src := range nonCandidates {
		if rep := s.Analyze(context.Background(), []byte(src)); rep.Status != phptaint.StatusNotCandidate {
			t.Fatalf("non-candidate %q returned %s (%s)", src, rep.Status, rep.Reason)
		}
	}
	if q := workerQueue(t, s, time.Now()); q.InFlight != 0 || q.Depth != 0 || q.DroppedTotal != 0 || s.SpawnCount() != 0 {
		t.Fatalf("non-candidates reached the worker: %+v spawns=%d", q, s.SpawnCount())
	}
	if err := s.Stop(); err != nil {
		t.Fatal(err)
	}
	if rep := s.Analyze(context.Background(), []byte(nonCandidates[0])); rep.Status != phptaint.StatusNotCandidate {
		t.Fatalf("stopped supervisor turned a non-candidate into %s", rep.Status)
	}
}

// The in-process answer must not reorder the checks the worker path makes
// first: an oversize source is still oversize and a withdrawn caller is
// still canceled, whatever the content.
func TestSupervisorNonCandidateKeepsSizeAndCancelOrder(t *testing.T) {
	s, err := NewSupervisor(helperChild(t, "ok"))
	if err != nil {
		t.Fatal(err)
	}
	if rep := s.Analyze(context.Background(), make([]byte, phptaint.MaxSourceBytes+1)); rep.Status != phptaint.StatusOversize {
		t.Fatalf("oversize non-candidate returned %s", rep.Status)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if rep := s.Analyze(ctx, []byte("<?php echo 'safe';")); rep.Status != phptaint.StatusCanceled {
		t.Fatalf("canceled non-candidate returned %s", rep.Status)
	}
}

// An oversize source never reaches a worker, so it is answered as oversize
// whatever state the worker side is in.
func TestSupervisorOversizeWinsOverOpenBreaker(t *testing.T) {
	s, err := NewSupervisor(SupervisorConfig{Command: filepath.Join(t.TempDir(), "missing-worker"), Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	for range ConsecutiveFailureLimit {
		s.Analyze(context.Background(), []byte(workerInput))
	}
	big := candidateOfSize(phptaint.MaxSourceBytes + 1)
	if rep := s.Analyze(context.Background(), big); rep.Status != phptaint.StatusOversize {
		t.Fatalf("open breaker: %s", rep.Status)
	}
	_ = s.Stop()
	if rep := s.Analyze(context.Background(), big); rep.Status != phptaint.StatusOversize {
		t.Fatalf("stopped: %s", rep.Status)
	}
}
