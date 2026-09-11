package checks

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/pidginhost/csm/internal/queuehealth"
)

const checkDispatchControlBudget = time.Minute

var checkDispatches = newCheckDispatchMonitor()

type checkDispatchMonitor struct {
	mu      sync.Mutex
	batches map[*checkDispatchBatch]struct{}
	losses  *queuehealth.Tracker
}

type checkDispatchBatch struct {
	monitor  *checkDispatchMonitor
	tasks    map[*checkDispatch]struct{}
	parallel int
	progress time.Time
	observer *CheckDispatchProgress
}

// All mutable task and batch fields are guarded by the monitor mutex.
type checkDispatch struct {
	batch    *checkDispatchBatch
	started  time.Time
	deadline time.Time
	failed   bool
}

func newCheckDispatchMonitor() *checkDispatchMonitor {
	return &checkDispatchMonitor{
		batches: make(map[*checkDispatchBatch]struct{}),
		losses:  queuehealth.New(0, time.Minute),
	}
}

func (m *checkDispatchMonitor) begin(count, parallel int) []*checkDispatch {
	now := time.Now()
	batch := &checkDispatchBatch{
		monitor: m, tasks: make(map[*checkDispatch]struct{}, count),
		parallel: parallel, progress: now,
	}
	tasks := make([]*checkDispatch, count)
	for i := range tasks {
		tasks[i] = &checkDispatch{batch: batch}
		batch.tasks[tasks[i]] = struct{}{}
	}
	if count > 0 {
		m.mu.Lock()
		m.batches[batch] = struct{}{}
		m.mu.Unlock()
	}
	return tasks
}

func (t *checkDispatch) admit() {
	m := t.batch.monitor
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	t.started = now
	t.deadline = now.Add(checkDispatchControlBudget)
	t.batch.progressed(now)
}

func (t *checkDispatch) executing(ctx context.Context) {
	if t == nil {
		return
	}
	// A caller without a deadline is unbounded rather than already overdue.
	deadline, _ := ctx.Deadline()
	m := t.batch.monitor
	m.mu.Lock()
	defer m.mu.Unlock()
	t.deadline = deadline
	t.batch.progressed(time.Now())
}

func (t *checkDispatch) returned() {
	if t == nil {
		return
	}
	m := t.batch.monitor
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	t.deadline = now.Add(checkDispatchControlBudget)
	t.batch.progressed(now)
}

func (t *checkDispatch) withdraw(ctx context.Context) {
	if t == nil || !errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return
	}
	m := t.batch.monitor
	m.mu.Lock()
	defer m.mu.Unlock()
	t.failLocked(time.Now())
}

func (t *checkDispatch) failLocked(now time.Time) {
	if !t.failed {
		t.failed = true
		t.batch.monitor.losses.Lose(now, 1)
	}
}

func (t *checkDispatch) wrap(fn func()) func() {
	return func() {
		completed := false
		defer func() {
			m := t.batch.monitor
			m.mu.Lock()
			defer m.mu.Unlock()
			now := time.Now()
			if !completed {
				t.failLocked(now)
			}
			delete(t.batch.tasks, t)
			t.batch.progressed(now)
			if len(t.batch.tasks) == 0 {
				delete(m.batches, t.batch)
				if t.batch.observer != nil {
					delete(t.batch.observer.batches, t.batch)
				}
			}
		}()
		fn()
		completed = true
	}
}

func (m *checkDispatchMonitor) QueueStatus(now time.Time) queuehealth.Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	status := m.losses.Snapshot(now)
	status.CapacityUnavailable = true
	status.LagBasis = "consumer_progress"
	var dispatchLate, runnerLate bool
	for batch := range m.batches {
		waiting, running := 0, 0
		for task := range batch.tasks {
			if task.started.IsZero() {
				waiting++
			} else {
				running++
				status.ProcessingSeconds = max(status.ProcessingSeconds, now.Sub(task.started).Seconds())
				runnerLate = runnerLate || overdue(now, task.deadline)
			}
		}
		status.Depth += waiting
		status.InFlight += running
		if waiting > 0 {
			lag := now.Sub(batch.progress)
			status.LagSeconds = max(status.LagSeconds, lag.Seconds())
			// A busy pool is expected while checks use their own budgets.
			// Free slots with no progress expose stalled dispatch separately.
			dispatchLate = dispatchLate || (running < batch.parallel && lag >= checkDispatchControlBudget)
		}
	}
	switch {
	case runnerLate:
		status.Reason = "processing_lag"
	case dispatchLate:
		status.Reason = "backlog_lag"
	}
	if status.Reason != "" {
		status.Status = "degraded"
	}
	return status
}

type checkDispatchContextKey struct{}

func withCheckDispatch(ctx context.Context, task *checkDispatch) context.Context {
	return context.WithValue(ctx, checkDispatchContextKey{}, task)
}

func checkDispatchFrom(ctx context.Context) *checkDispatch {
	task, _ := ctx.Value(checkDispatchContextKey{}).(*checkDispatch)
	return task
}

// CheckDispatchQueueStatus measures pending checks and their runner wrappers.
func CheckDispatchQueueStatus(now time.Time) queuehealth.Status {
	return checkDispatches.QueueStatus(now)
}
