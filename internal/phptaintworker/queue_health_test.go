package phptaintworker

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/phptaint"
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

func TestWorkerQueueSpawnFailuresAndBreakerRefusals(t *testing.T) {
	s, err := NewSupervisor(SupervisorConfig{Command: filepath.Join(t.TempDir(), "missing-worker"), Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 6; i++ {
		if rep := s.Analyze(context.Background(), []byte(workerInput)); rep.Status != phptaint.StatusWorkerFailure {
			t.Fatalf("failed/refused request %d returned %s", i, rep.Status)
		}
	}
	if q := workerQueue(t, s, time.Now()); q.InFlight != 0 || q.Depth != 0 || q.DroppedTotal != 6 || q.Reason != "dropped_work" || s.SpawnCount() != 0 {
		t.Fatalf("spawn/refusal evidence: %+v spawns=%d", q, s.SpawnCount())
	}
	if err := s.Stop(); err != nil {
		t.Fatal(err)
	}
	if rep := s.Analyze(context.Background(), []byte(workerInput)); rep.Status != phptaint.StatusWorkerFailure || rep.Reason != "worker_failure: supervisor stopped" {
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
	if consecutive := s.proc.Stats().ConsecutiveFailures; consecutive != 0 {
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
