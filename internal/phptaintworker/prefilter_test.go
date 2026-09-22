package phptaintworker

import (
	"context"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/phptaint"
)

// Cancel just after the first Err observation, so cancellation between the
// initial check and the pre-filter's answer does not depend on scan timing.
type cancelAfterErrContext struct {
	context.Context
	cancel context.CancelFunc
	once   sync.Once
}

func (c *cancelAfterErrContext) Err() error {
	err := c.Context.Err()
	c.once.Do(c.cancel)
	return err
}

func TestSupervisorCancellationDuringPrefilter(t *testing.T) {
	s, err := NewSupervisor(helperChild(t, "hang"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Stop() })
	parent, cancel := context.WithCancel(context.Background())
	defer cancel()
	ctx := &cancelAfterErrContext{Context: parent, cancel: cancel}
	rep := s.Analyze(ctx, []byte("<?php echo 'safe';"))
	if rep.Status != phptaint.StatusCanceled || rep.Reason != "canceled: context canceled" {
		t.Fatalf("cancellation during the pre-filter returned %+v", rep)
	}
}

func TestSupervisorPrefilterBypassesBusyWorker(t *testing.T) {
	cfg := helperChild(t, "ok")
	cfg.Timeout = time.Minute
	s, err := NewSupervisor(cfg)
	if err != nil {
		t.Fatal(err)
	}
	entered, release := installHeldReply(t, s)
	t.Cleanup(func() { release(); _ = s.Stop() })
	workerDone := make(chan phptaint.Report, 1)
	go func() { workerDone <- s.Analyze(context.Background(), []byte(workerInput)) }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("candidate did not reach the worker")
	}

	for _, canceled := range []bool{false, true} {
		ctx := context.Background()
		want := phptaint.StatusNotCandidate
		if canceled {
			parent, cancel := context.WithCancel(ctx)
			defer cancel()
			ctx = &cancelAfterErrContext{Context: parent, cancel: cancel}
			want = phptaint.StatusCanceled
		}
		localDone := make(chan phptaint.Report, 1)
		go func() { localDone <- s.Analyze(ctx, []byte("<?php echo 'safe';")) }()
		select {
		case rep := <-localDone:
			if rep.Status != want {
				t.Fatalf("local answer = %s, want %s", rep.Status, want)
			}
		case <-time.After(time.Second):
			t.Fatal("pre-filter queued behind the busy worker")
		}
		if q := workerQueue(t, s, time.Now()); q.Depth != 0 || q.InFlight != 1 || q.DroppedTotal != 0 || q.Status != "ok" {
			t.Fatalf("local answer changed worker accounting: %+v", q)
		}
	}
	release()
	select {
	case rep := <-workerDone:
		if rep.Status != phptaint.StatusNotCandidate {
			t.Fatalf("local answers disrupted the worker: %+v", rep)
		}
	case <-time.After(time.Second):
		t.Fatal("worker did not finish after release")
	}
	waitWorkerQueueIdle(t, s, 0)
}

func TestSupervisorPrefilterPreservesOpenBreaker(t *testing.T) {
	s, err := NewSupervisor(SupervisorConfig{Command: filepath.Join(t.TempDir(), "missing-worker"), Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Stop() })
	for range ConsecutiveFailureLimit {
		if rep := s.Analyze(context.Background(), []byte(workerInput)); rep.Status != phptaint.StatusWorkerFailure {
			t.Fatalf("missing worker returned %+v", rep)
		}
	}
	openedAt := s.openedAt
	for _, src := range [][]byte{nil, []byte("<?php echo 'safe';"), []byte("\x89PNG\r\n\x1a\n\x00"), make([]byte, phptaint.MaxSourceBytes)} {
		if rep := s.Analyze(context.Background(), src); rep.Status != phptaint.StatusNotCandidate {
			t.Fatalf("open breaker rejected a non-candidate: %+v", rep)
		}
	}
	if s.consecutive != ConsecutiveFailureLimit || s.openedAt != openedAt || !s.breakerOpenLocked() {
		t.Fatal("local answers changed the open breaker")
	}
	if q := workerQueue(t, s, time.Now()); q.Depth != 0 || q.InFlight != 0 || q.DroppedTotal != ConsecutiveFailureLimit || s.SpawnCount() != 0 {
		t.Fatalf("local answers changed worker accounting: %+v", q)
	}
}

func TestSupervisorPrefilterSizeBeforeCancellation(t *testing.T) {
	s, err := NewSupervisor(helperChild(t, "ok"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Stop() })
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, candidate := range []bool{false, true} {
		for _, size := range []int{phptaint.MaxSourceBytes, phptaint.MaxSourceBytes + 1} {
			src := make([]byte, size)
			if candidate {
				copy(src, workerInput)
			}
			want := phptaint.StatusCanceled
			if size > phptaint.MaxSourceBytes {
				want = phptaint.StatusOversize
			}
			if rep := s.Analyze(ctx, src); rep.Status != want {
				t.Fatalf("candidate=%v size=%d: status=%s, want %s", candidate, size, rep.Status, want)
			}
		}
	}
	if s.SpawnCount() != 0 {
		t.Fatal("rejected input spawned a worker")
	}
}
