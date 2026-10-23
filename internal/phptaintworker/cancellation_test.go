package phptaintworker

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/phptaint"
)

// Cancel after admission checks the context, before the launcher checks it.
// Returning the observed value models cancellation just after Err returns.
type cancelBeforeLaunchContext struct {
	context.Context
	cancel context.CancelFunc
	calls  atomic.Int32
}

func (c *cancelBeforeLaunchContext) Err() error {
	err := c.Context.Err()
	if c.calls.Add(1) == 2 {
		c.cancel()
	}
	return err
}

func TestSupervisorCancellationBeforeLaunchIsNotWorkerFailure(t *testing.T) {
	s, err := NewSupervisor(helperChild(t, "hang"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Stop() })
	for range ConsecutiveFailureLimit {
		parent, cancel := context.WithCancel(context.Background())
		ctx := &cancelBeforeLaunchContext{Context: parent, cancel: cancel}
		rep := s.Analyze(ctx, []byte(workerInput))
		cancel()
		if rep.Status != phptaint.StatusCanceled || rep.Reason != "canceled: context canceled" {
			t.Errorf("cancellation before launch returned %+v", rep)
		}
	}
	waitWorkerQueueIdle(t, s, 0)
	s.SetMode("ok")
	rep := s.Analyze(context.Background(), []byte(workerInput))
	if rep.Status != phptaint.StatusAnalyzed || rep.TotalResults != 1 || len(rep.Results) != 1 {
		t.Fatalf("startup cancellations prevented the next analysis: %+v", rep)
	}
	if q := workerQueue(t, s, time.Now()); q.Status != "ok" || q.DroppedTotal != 0 {
		t.Fatalf("startup cancellations counted as request loss: %+v", q)
	}
}
