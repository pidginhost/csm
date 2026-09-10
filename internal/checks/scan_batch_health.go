package checks

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/pidginhost/csm/internal/queuehealth"
)

type scanBatchMonitor struct {
	mu      sync.Mutex
	batches map[*scanBatch]struct{}
	losses  *queuehealth.Tracker
}

type scanBatch struct {
	monitor  *scanBatchMonitor
	tasks    []*scanBatchTask
	pending  map[*scanBatchTask]struct{}
	parallel int
	progress time.Time
}

// Mutable batch and task state is guarded by the monitor mutex.
type scanBatchTask struct {
	batch             *scanBatch
	started, deadline time.Time
	failed            bool
}

func newScanBatchMonitor() *scanBatchMonitor {
	return &scanBatchMonitor{batches: make(map[*scanBatch]struct{}), losses: queuehealth.New(0, time.Minute)}
}

func (m *scanBatchMonitor) begin(count, parallel int) *scanBatch {
	b := &scanBatch{monitor: m, tasks: make([]*scanBatchTask, count), pending: make(map[*scanBatchTask]struct{}, count), parallel: parallel, progress: time.Now()}
	for i := range b.tasks {
		b.tasks[i] = &scanBatchTask{batch: b}
		b.pending[b.tasks[i]] = struct{}{}
	}
	if count > 0 {
		m.mu.Lock()
		m.batches[b] = struct{}{}
		m.mu.Unlock()
	}
	return b
}

func (t *scanBatchTask) admit() {
	m := t.batch.monitor
	m.mu.Lock()
	defer m.mu.Unlock()
	t.started = time.Now()
	t.deadline = t.started.Add(time.Minute)
	t.batch.progress = t.started
}

func (t *scanBatchTask) executing(ctx context.Context, budget time.Duration) {
	deadline := time.Now().Add(budget)
	if parent, ok := ctx.Deadline(); ok && parent.Before(deadline) {
		deadline = parent
	}
	m := t.batch.monitor
	m.mu.Lock()
	t.deadline = deadline
	m.mu.Unlock()
}

func (t *scanBatchTask) progress() {
	m := t.batch.monitor
	m.mu.Lock()
	t.deadline = time.Now().Add(time.Minute)
	m.mu.Unlock()
}

func (t *scanBatchTask) failLocked() {
	if !t.failed {
		t.failed = true
		t.batch.monitor.losses.Lose(time.Now(), 1)
	}
}

func (t *scanBatchTask) fail() {
	m := t.batch.monitor
	m.mu.Lock()
	t.failLocked()
	m.mu.Unlock()
}

func (t *scanBatchTask) finish() {
	m := t.batch.monitor
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(t.batch.pending, t)
	t.batch.progress = time.Now()
	if len(t.batch.pending) == 0 {
		delete(m.batches, t.batch)
	}
}

func (t *scanBatchTask) run(ctx context.Context, budget time.Duration, fn func()) {
	completed := false
	defer func() {
		if !completed || errors.Is(ctx.Err(), context.DeadlineExceeded) {
			t.fail()
		}
		t.finish()
	}()
	t.executing(ctx, budget)
	fn()
	completed = true
}

// abandon runs after dispatch has stopped. Running workers retain their own
// tasks, including when a caller has canceled but an operation ignores it.
func (b *scanBatch) abandon(ctx context.Context) {
	m := b.monitor
	m.mu.Lock()
	defer m.mu.Unlock()
	for task := range b.pending {
		if !task.started.IsZero() {
			continue
		}
		if !errors.Is(ctx.Err(), context.Canceled) {
			task.failLocked()
		}
		delete(b.pending, task)
	}
	if len(b.pending) == 0 {
		delete(m.batches, b)
	}
}

func (m *scanBatchMonitor) snapshot(now time.Time) queuehealth.Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.losses.Snapshot(now)
	s.CapacityUnavailable = true
	s.LagBasis = "consumer_progress"
	var waitingLate, runningLate bool
	for b := range m.batches {
		waiting, running := 0, 0
		for task := range b.pending {
			if task.started.IsZero() {
				waiting++
			} else {
				running++
				s.ProcessingSeconds = max(s.ProcessingSeconds, now.Sub(task.started).Seconds())
				runningLate = runningLate || !now.Before(task.deadline)
			}
		}
		s.Depth += waiting
		s.InFlight += running
		if waiting > 0 {
			lag := now.Sub(b.progress)
			s.LagSeconds = max(s.LagSeconds, lag.Seconds())
			// Filling a finite batch is expected while every worker is busy.
			// Its own deadlines bound that work; a free slot needs progress.
			waitingLate = waitingLate || (running < b.parallel && lag >= time.Minute)
		}
	}
	switch {
	case runningLate:
		s.Reason = "processing_lag"
	case waitingLate:
		s.Reason = "backlog_lag"
	}
	if s.Reason != "" {
		s.Status = "degraded"
	}
	return s
}
