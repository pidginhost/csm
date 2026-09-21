package phptaintworker

import (
	"bytes"
	"context"
	"io"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/phptaint"
	"github.com/pidginhost/csm/internal/phptaintipc"
	"github.com/pidginhost/csm/internal/queuehealth"
)

func workerQueue(t *testing.T, s *Supervisor, now time.Time) queuehealth.Status {
	t.Helper()
	source, ok := any(s).(interface {
		QueueStatuses(time.Time) map[string]queuehealth.Status
	})
	if !ok {
		t.Fatal("PHP worker requests have no queue health source")
	}
	done := make(chan map[string]queuehealth.Status, 1)
	go func() { done <- source.QueueStatuses(now) }()
	select {
	case rows := <-done:
		status, exists := rows["requests"]
		if !exists || len(rows) != 1 {
			t.Fatalf("missing or unexpected worker queue rows: %+v", rows)
		}
		return status
	case <-time.After(time.Second):
		t.Fatal("health snapshot waited on the worker or its admission lock")
		return queuehealth.Status{}
	}
}

func TestWorkerQueuePublication(t *testing.T) {
	s, err := NewSupervisor(helperChild(t, "ok"))
	if err != nil {
		t.Fatal(err)
	}
	q := workerQueue(t, s, time.Now())
	if q.Status != "ok" || q.Depth != 0 || q.InFlight != 0 || q.DroppedTotal != 0 || !q.CapacityUnavailable {
		t.Fatalf("idle worker queue: %+v", q)
	}
}

func TestWorkerQueueWaitingCallersCancelWithoutLoss(t *testing.T) {
	s, err := NewSupervisor(helperChild(t, "ok"))
	if err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	unlock := sync.OnceFunc(s.mu.Unlock)
	defer unlock()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	results := make(chan phptaint.Report, 3)
	for range 3 {
		go func() { results <- s.Analyze(ctx, []byte("<?php echo 'safe';")) }()
	}
	until := time.Now().Add(time.Second)
	for {
		q := workerQueue(t, s, time.Now().Add(61*time.Second))
		if q.Depth == 3 {
			if q.InFlight != 0 || q.Reason != "backlog_lag" || q.DroppedTotal != 0 || !q.CapacityUnavailable {
				t.Fatalf("blocked admission: %+v", q)
			}
			break
		}
		if time.Now().After(until) {
			t.Fatalf("callers did not publish before the lock: %+v", q)
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	unlock()
	for range 3 {
		select {
		case rep := <-results:
			if rep.Status != phptaint.StatusCanceled {
				t.Fatalf("waiting cancellation became %s", rep.Status)
			}
		case <-time.After(time.Second):
			t.Fatal("waiting caller did not return after lock release")
		}
	}
	if q := workerQueue(t, s, time.Now()); q.Depth != 0 || q.InFlight != 0 || q.DroppedTotal != 0 || q.Status != "ok" || s.SpawnCount() != 0 {
		t.Fatalf("canceled callers retained work or spawned: %+v spawns=%d", q, s.SpawnCount())
	}
}

type discardRequestPipe struct{}

func (discardRequestPipe) Write(p []byte) (int, error) { return len(p), nil }
func (discardRequestPipe) Close() error                { return nil }

type heldReplyPipe struct {
	entered chan struct{}
	release <-chan struct{}
	reader  io.Reader
	once    sync.Once
}

func (p *heldReplyPipe) Read(buf []byte) (int, error) {
	p.once.Do(func() { close(p.entered) })
	<-p.release
	return p.reader.Read(buf)
}
func (*heldReplyPipe) Close() error { return nil }

func installHeldReply(t *testing.T, s *Supervisor) (<-chan struct{}, func()) {
	t.Helper()
	frame, err := phptaintipc.EncodePayload("", phptaintipc.AnalyzeResult{Report: phptaint.Report{Status: phptaint.StatusNotCandidate}})
	if err != nil {
		t.Fatal(err)
	}
	var data bytes.Buffer
	if err := phptaintipc.WriteFrame(&data, frame); err != nil {
		t.Fatal(err)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	done := make(chan struct{})
	close(done)
	s.child = &child{cmd: &exec.Cmd{}, stdin: discardRequestPipe{}, stdout: &heldReplyPipe{entered: entered, release: release, reader: bytes.NewReader(data.Bytes())}, done: done}
	return entered, sync.OnceFunc(func() { close(release) })
}

func TestWorkerQueueRetainsRPCBeyondCallerCancellation(t *testing.T) {
	s, err := NewSupervisor(helperChild(t, "ok"))
	if err != nil {
		t.Fatal(err)
	}
	entered, release := installHeldReply(t, s)
	defer release()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan phptaint.Report, 1)
	go func() { done <- s.Analyze(ctx, []byte("<?php echo 'safe';")) }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("RPC did not start")
	}
	if q := workerQueue(t, s, time.Now()); q.Depth != 0 || q.InFlight != 1 || q.Status != "ok" || q.DroppedTotal != 0 {
		t.Fatalf("live RPC: %+v", q)
	}
	cancel()
	select {
	case rep := <-done:
		if rep.Status != phptaint.StatusCanceled {
			t.Fatalf("canceled RPC became %s", rep.Status)
		}
	case <-time.After(time.Second):
		t.Fatal("caller did not return after cancellation")
	}
	if q := workerQueue(t, s, time.Now().Add(3*time.Second)); q.Depth != 0 || q.InFlight != 1 || q.Reason != "processing_lag" || q.DroppedTotal != 0 {
		t.Fatalf("caller cancellation hid a pipe operation: %+v", q)
	}
	release()
	until := time.Now().Add(time.Second)
	for {
		q := workerQueue(t, s, time.Now())
		if q.InFlight == 0 {
			if q.Depth != 0 || q.DroppedTotal != 0 || q.Status != "ok" {
				t.Fatalf("late RPC completion: %+v", q)
			}
			break
		}
		if time.Now().After(until) {
			t.Fatalf("finished RPC kept ownership: %+v", q)
		}
		time.Sleep(time.Millisecond)
	}
}

func TestWorkerQueueTimeoutLossSurvivesLateReply(t *testing.T) {
	cfg := helperChild(t, "ok")
	cfg.Timeout = 20 * time.Millisecond
	s, err := NewSupervisor(cfg)
	if err != nil {
		t.Fatal(err)
	}
	_, release := installHeldReply(t, s)
	defer release()
	rep := s.Analyze(context.Background(), []byte("<?php echo 'safe';"))
	if rep.Status != phptaint.StatusTimeout {
		t.Fatalf("timeout became %s", rep.Status)
	}
	if q := workerQueue(t, s, time.Now()); q.InFlight != 1 || q.Depth != 0 || q.DroppedTotal != 1 || q.Reason != "processing_lag" {
		t.Fatalf("timed-out RPC ownership: %+v", q)
	}
	release()
	until := time.Now().Add(time.Second)
	for {
		q := workerQueue(t, s, time.Now().Add(time.Minute))
		if q.InFlight == 0 {
			if q.Depth != 0 || q.DroppedTotal != 1 || q.RecentDrops != 0 || q.Status != "ok" {
				t.Fatalf("timeout recovery: %+v", q)
			}
			break
		}
		if time.Now().After(until) {
			t.Fatalf("late reply did not release ownership: %+v", q)
		}
		time.Sleep(time.Millisecond)
	}
}

func TestWorkerQueueKnownFailureDuringCleanup(t *testing.T) {
	cfg := helperChild(t, "hang")
	cfg.Timeout = 100 * time.Millisecond
	entered, release := make(chan struct{}), make(chan struct{})
	finish := sync.OnceFunc(func() { close(release) })
	defer finish()
	cfg.Log = func(string, ...any) { close(entered); <-release }
	s, err := NewSupervisor(cfg)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan phptaint.Report, 1)
	go func() { done <- s.Analyze(context.Background(), []byte("<?php echo 'safe';")) }()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("timeout did not reach cleanup")
	}
	if q := workerQueue(t, s, time.Now().Add(61*time.Second)); q.Depth != 0 || q.InFlight != 1 || q.DroppedTotal != 1 || q.Reason != "processing_lag" {
		t.Fatalf("cleanup hid a known timeout: %+v", q)
	}
	finish()
	select {
	case rep := <-done:
		if rep.Status != phptaint.StatusTimeout {
			t.Fatalf("cleanup changed timeout: %s", rep.Status)
		}
	case <-time.After(time.Second):
		t.Fatal("cleanup did not finish")
	}
	if q := workerQueue(t, s, time.Now()); q.Depth != 0 || q.InFlight != 0 || q.DroppedTotal != 1 {
		t.Fatalf("cleanup released the wrong work: %+v", q)
	}
}

func TestWorkerQueueSpawnFailuresAndBreakerRefusals(t *testing.T) {
	s, err := NewSupervisor(SupervisorConfig{Command: filepath.Join(t.TempDir(), "missing-worker"), Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 6; i++ {
		if rep := s.Analyze(context.Background(), []byte("<?php echo 'safe';")); rep.Status != phptaint.StatusWorkerFailure {
			t.Fatalf("failed/refused request %d returned %s", i, rep.Status)
		}
	}
	if q := workerQueue(t, s, time.Now()); q.InFlight != 0 || q.Depth != 0 || q.DroppedTotal != 6 || q.Reason != "dropped_work" || s.SpawnCount() != 0 {
		t.Fatalf("spawn/refusal evidence: %+v spawns=%d", q, s.SpawnCount())
	}
	if err := s.Stop(); err != nil {
		t.Fatal(err)
	}
	if rep := s.Analyze(context.Background(), []byte("<?php echo 'safe';")); rep.Status != phptaint.StatusWorkerFailure || rep.Reason != "worker_failure: supervisor stopped" {
		t.Fatalf("stopped supervisor accepted work: %+v", rep)
	}
	if q := workerQueue(t, s, time.Now().Add(time.Minute)); q.Status != "ok" || q.DroppedTotal != 6 || q.Depth != 0 || q.InFlight != 0 {
		t.Fatalf("intentional stop added losses or lost evidence: %+v", q)
	}
}

func TestWorkerQueueRejectedInputHasNoLoss(t *testing.T) {
	s, err := NewSupervisor(helperChild(t, "ok"))
	if err != nil {
		t.Fatal(err)
	}
	if rep := s.Analyze(context.Background(), make([]byte, phptaint.MaxSourceBytes+1)); rep.Status != phptaint.StatusOversize {
		t.Fatalf("oversize input returned %s", rep.Status)
	}
	if q := workerQueue(t, s, time.Now()); q.InFlight != 0 || q.Depth != 0 || q.DroppedTotal != 0 || q.Status != "ok" || s.SpawnCount() != 0 {
		t.Fatalf("input limit counted as failed work or spawned: %+v spawns=%d", q, s.SpawnCount())
	}
}

func TestWorkerQueueHonorsLongConfiguredRPC(t *testing.T) {
	cfg := helperChild(t, "ok")
	cfg.Timeout = 5 * time.Minute
	s, err := NewSupervisor(cfg)
	if err != nil {
		t.Fatal(err)
	}
	entered, release := installHeldReply(t, s)
	defer func() { release(); _ = s.Stop() }()
	done := make(chan phptaint.Report, 1)
	go func() { done <- s.Analyze(context.Background(), []byte("<?php echo 'safe';")) }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("RPC did not start")
	}
	if q := workerQueue(t, s, time.Now().Add(61*time.Second)); q.InFlight != 1 || q.Depth != 0 || q.Status != "ok" || q.DroppedTotal != 0 {
		t.Fatalf("healthy RPC borrowed the setup budget: %+v", q)
	}
	release()
	select {
	case rep := <-done:
		if rep.Status != phptaint.StatusNotCandidate {
			t.Fatalf("valid reply changed: %+v", rep)
		}
	case <-time.After(time.Second):
		t.Fatal("valid reply was not consumed")
	}
	waitWorkerQueueIdle(t, s, 0)
}

func waitWorkerQueueIdle(t *testing.T, s *Supervisor, losses uint64) {
	t.Helper()
	until := time.Now().Add(time.Second)
	for {
		q := workerQueue(t, s, time.Now())
		if q.InFlight == 0 && q.Depth == 0 {
			if q.DroppedTotal != losses {
				t.Fatalf("settled request losses: %+v want=%d", q, losses)
			}
			return
		}
		if time.Now().After(until) {
			t.Fatalf("request did not release ownership: %+v", q)
		}
		time.Sleep(time.Millisecond)
	}
}

type heldWorkerContext struct {
	context.Context
	entered chan struct{}
	release <-chan struct{}
}

func (c heldWorkerContext) Done() <-chan struct{} {
	close(c.entered)
	<-c.release
	return c.Context.Done()
}

func TestWorkerQueueBufferedReplyHasIndependentBudget(t *testing.T) {
	cfg := helperChild(t, "ok")
	cfg.Timeout = 5 * time.Minute
	s, err := NewSupervisor(cfg)
	if err != nil {
		t.Fatal(err)
	}
	_, releaseReply := installHeldReply(t, s)
	releaseReply()
	entered, release := make(chan struct{}), make(chan struct{})
	finish := sync.OnceFunc(func() { close(release) })
	defer func() { finish(); _ = s.Stop() }()
	done := make(chan phptaint.Report, 1)
	go func() {
		done <- s.Analyze(heldWorkerContext{context.Background(), entered, release}, []byte("<?php echo 'safe';"))
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("reply consumer did not reach context select")
	}
	until := time.Now().Add(time.Second)
	for {
		q := workerQueue(t, s, time.Now().Add(61*time.Second))
		if q.Reason == "processing_lag" {
			if q.InFlight != 1 || q.Depth != 0 || q.DroppedTotal != 0 {
				t.Fatalf("buffered reply ownership: %+v", q)
			}
			break
		}
		if time.Now().After(until) {
			t.Fatalf("buffered reply borrowed RPC budget: %+v", q)
		}
		time.Sleep(time.Millisecond)
	}
	finish()
	select {
	case rep := <-done:
		if rep.Status != phptaint.StatusNotCandidate {
			t.Fatalf("buffered reply changed: %+v", rep)
		}
	case <-time.After(time.Second):
		t.Fatal("buffered reply was not consumed")
	}
	waitWorkerQueueIdle(t, s, 0)
}

type exitingReplyPipe struct{}

func (exitingReplyPipe) Read([]byte) (int, error) { runtime.Goexit(); return 0, io.EOF }
func (exitingReplyPipe) Close() error             { return nil }

func TestWorkerQueueRPCExitCountsOnce(t *testing.T) {
	cfg := helperChild(t, "ok")
	cfg.Timeout = 20 * time.Millisecond
	s, err := NewSupervisor(cfg)
	if err != nil {
		t.Fatal(err)
	}
	_, release := installHeldReply(t, s)
	release()
	s.child.stdout = exitingReplyPipe{}
	rep := s.Analyze(context.Background(), []byte("<?php echo 'safe';"))
	if rep.Status != phptaint.StatusTimeout {
		t.Fatalf("missing RPC reply changed status: %s", rep.Status)
	}
	waitWorkerQueueIdle(t, s, 1)
}

func TestWorkerQueueRecoveredAnalyzerPanicCountsLoss(t *testing.T) {
	s, err := NewSupervisor(helperChild(t, "ok"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Stop() }()
	for _, src := range []string{
		"<?php $x = curl_exec($c); eval($x); }",
		// Text syntax-highlighting rules can contain PHP tokens without NULs.
		`var rules = ["<?php", "}", "curl_exec", "eval"];`,
		"<?php $x = curl_exec($c); eval($x); }",
	} {
		rep := s.Analyze(context.Background(), []byte(src))
		if rep.Status != phptaint.StatusPanic || len(rep.Results) != 0 || rep.Reason != "panic: recovered panic during analysis" {
			t.Fatalf("recovered analyzer panic report changed: status=%s results=%d", rep.Status, len(rep.Results))
		}
	}
	// Existing recovery and breaker policy must remain intact.
	rep := s.Analyze(context.Background(), []byte("<?php $x = curl_exec($c); eval($x);"))
	if rep.Status != phptaint.StatusAnalyzed || rep.TotalResults != 1 || len(rep.Results) != 1 || s.SpawnCount() != 1 {
		t.Fatalf("successful recovery changed: status=%s results=%d spawns=%d", rep.Status, len(rep.Results), s.SpawnCount())
	}
	s.mu.Lock()
	consecutive := s.consecutive
	s.mu.Unlock()
	if consecutive != 0 {
		t.Fatalf("recovered panic changed breaker state: failures=%d", consecutive)
	}
	waitWorkerQueueIdle(t, s, 3)
	q := workerQueue(t, s, time.Now())
	if q.Status != "degraded" || q.Reason != "dropped_work" || q.DroppedTotal != 3 || q.RecentDrops != 3 {
		t.Fatalf("three actual failed analyses are missing from request health: %+v", q)
	}
	q = workerQueue(t, s, time.Now().Add(time.Minute))
	if q.Status != "ok" || q.DroppedTotal != 3 || q.RecentDrops != 0 || q.Depth != 0 || q.InFlight != 0 {
		t.Fatalf("recovered analyzer loss evidence was not retained: %+v", q)
	}
}
