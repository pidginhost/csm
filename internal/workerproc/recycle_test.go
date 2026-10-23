package workerproc

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"sync/atomic"
	"testing"
	"time"
)

func newRecycleSupervisor(t *testing.T, cfg Config) *Supervisor {
	t.Helper()
	cfg.Name = "test worker"
	cfg.Timeout = 5 * time.Second
	cfg.Limits = Limits{MaxFrameBytes: 1 << 20, MaxFDs: 4}
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Stop() })
	return s
}

// sleepHandler sleeps for the number of milliseconds in the payload.
func sleepHandler(_ context.Context, req Frame, _ []*os.File) (Frame, []*os.File) {
	var ms int
	if err := json.Unmarshal(req.Payload, &ms); err != nil {
		return Frame{Error: err.Error()}, nil
	}
	time.Sleep(time.Duration(ms) * time.Millisecond)
	return Frame{Payload: json.RawMessage(`{}`)}, nil
}

func sleepCall(t *testing.T, s *Supervisor, ms int) {
	t.Helper()
	payload, _ := json.Marshal(ms)
	if _, _, err := s.Call(context.Background(), Frame{Op: "sleep", Payload: payload}, nil, okCheck); err != nil {
		t.Fatal(err)
	}
}

func TestCallRecyclesAfterMaxJobs(t *testing.T) {
	s := newRecycleSupervisor(t, Config{Launch: pairLauncher(t, sleepHandler), MaxJobs: 2})
	for range 5 {
		sleepCall(t, s, 0)
	}
	if st := s.Stats(); st.Spawns != 3 || st.ConsecutiveFailures != 0 {
		t.Fatalf("stats = %+v, want 3 spawns and no failures", st)
	}
	waitWorkerQueueIdle(t, s, 0)
}

// retiringProcess asks to retire after its first job.
type retiringProcess struct {
	Process
	asked atomic.Bool
}

func (p *retiringProcess) Retire() bool { return !p.asked.Swap(true) }

func TestCallRecyclesWhenWorkerAsksToRetire(t *testing.T) {
	inner := pairLauncher(t, sleepHandler)
	var first Process
	launch := func(ctx context.Context) (Process, error) {
		p, err := inner(ctx)
		if err != nil {
			return nil, err
		}
		if first == nil {
			first = &retiringProcess{Process: p}
			return first, nil
		}
		return p, nil
	}
	s := newRecycleSupervisor(t, Config{Launch: launch})
	sleepCall(t, s, 0)
	sleepCall(t, s, 0)
	if got := s.Stats().Spawns; got != 2 {
		t.Fatalf("spawns = %d, want a new worker after retirement", got)
	}
	select {
	case <-first.Done():
	default:
		t.Fatal("retired worker still running")
	}
	if got := s.Stats().ConsecutiveFailures; got != 0 {
		t.Fatalf("retirement counted as failure: %d", got)
	}
}

func TestIdleWorkerIsStopped(t *testing.T) {
	s := newRecycleSupervisor(t, Config{Launch: pairLauncher(t, sleepHandler), IdleTimeout: 50 * time.Millisecond})
	sleepCall(t, s, 0)
	if !s.Stats().Running {
		t.Fatal("worker not running after a call")
	}
	deadline := time.Now().Add(2 * time.Second)
	for s.Stats().Running {
		if time.Now().After(deadline) {
			t.Fatal("idle worker was not stopped")
		}
		time.Sleep(5 * time.Millisecond)
	}
	sleepCall(t, s, 0)
	if got := s.Stats().Spawns; got != 2 {
		t.Fatalf("spawns = %d, want 2", got)
	}
}

func TestIdleTimerSparesBusyWorker(t *testing.T) {
	s := newRecycleSupervisor(t, Config{Launch: pairLauncher(t, sleepHandler), IdleTimeout: 50 * time.Millisecond})
	sleepCall(t, s, 0)
	time.Sleep(40 * time.Millisecond)
	sleepCall(t, s, 300)
	if got := s.Stats().Spawns; got != 1 {
		t.Fatalf("spawns = %d, idle timer killed a busy worker", got)
	}
}

func TestStopCancelsIdleTimer(t *testing.T) {
	s := newRecycleSupervisor(t, Config{Launch: pairLauncher(t, sleepHandler), IdleTimeout: 50 * time.Millisecond})
	sleepCall(t, s, 0)
	if err := s.Stop(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond)
	if s.Stats().Running {
		t.Fatal("worker running after Stop")
	}
	if _, _, err := s.Call(context.Background(), Frame{Op: "sleep", Payload: json.RawMessage(`0`)}, nil, okCheck); !errors.Is(err, ErrStopped) {
		t.Fatalf("Call after Stop = %v", err)
	}
}
