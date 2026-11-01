package workerproc

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestCallGuardedRefusalKeepsWorker(t *testing.T) {
	s := newTestSupervisor(t, helperLauncher(t, "echo"), time.Second)
	request := Frame{Op: "work"}
	if _, _, err := s.Call(context.Background(), request, nil, okCheck); err != nil {
		t.Fatal(err)
	}
	pid := s.Stats().LastPID
	refused := errors.New("input refused")
	finished := false
	_, _, err := s.CallGuarded(context.Background(), request, nil, okCheck,
		func() error { return refused }, func(error) { finished = true })
	if !errors.Is(err, refused) || finished {
		t.Fatalf("refusal = %v, after called=%v", err, finished)
	}
	stats := s.Stats()
	if !stats.Running || stats.Spawns != 1 || stats.LastPID != pid || len(stats.Kills) != 0 {
		t.Fatalf("guard refusal changed the worker: %+v", stats)
	}
	if q := workerQueue(t, s, time.Now()); q.Depth != 0 || q.InFlight != 0 || q.DroppedTotal != 1 {
		t.Fatalf("guard refusal queue = %+v", q)
	}
	if _, _, err := s.Call(context.Background(), request, nil, okCheck); err != nil {
		t.Fatalf("worker unusable after guard refusal: %v", err)
	}
}

func TestCallGuardedReportsResult(t *testing.T) {
	for _, mode := range []string{"echo", "reply-error"} {
		t.Run(mode, func(t *testing.T) {
			s := newTestSupervisor(t, helperLauncher(t, mode), time.Second)
			beforeCalls, afterCalls := 0, 0
			var result error
			_, _, err := s.CallGuarded(context.Background(), Frame{Op: "work"}, nil, okCheck,
				func() error { beforeCalls++; return nil },
				func(err error) { afterCalls++; result = err })
			if beforeCalls != 1 || afterCalls != 1 || result != err {
				t.Fatalf("before=%d after=%d result=%v call=%v", beforeCalls, afterCalls, result, err)
			}
			if mode == "reply-error" && !errors.Is(result, ErrWorkerFailed) || mode == "echo" && result != nil {
				t.Fatalf("result = %v for %s", result, mode)
			}
		})
	}
}

func TestCallGuardedSkipsCallbacksAfterCancellation(t *testing.T) {
	s := newTestSupervisor(t, helperLauncher(t, "echo"), time.Second)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _, err := s.CallGuarded(ctx, Frame{Op: "work"}, nil, okCheck,
		func() error { t.Error("guard ran after cancellation"); return nil },
		func(error) { t.Error("completion ran after cancellation") })
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled call = %v", err)
	}
	if q := workerQueue(t, s, time.Now()); q.Depth != 0 || q.InFlight != 0 || q.DroppedTotal != 0 {
		t.Fatalf("canceled guard queue = %+v", q)
	}
}
