package checks

import (
	"context"
	"time"
)

// DispatchProgressSnapshot measures only the check batches owned by one caller.
// LastProgress remains available after the last wrapper exits, so its caller
// can time result handling without borrowing the completed check's budget.
type DispatchProgressSnapshot struct {
	Active       bool
	Overdue      bool
	LastProgress time.Time
}

// CheckDispatchProgress is memory-only evidence for a scan's orchestration.
// All fields are guarded by the owning dispatch monitor's mutex.
type CheckDispatchProgress struct {
	monitor *checkDispatchMonitor
	batches map[*checkDispatchBatch]struct{}
	last    time.Time
}

type dispatchProgressContextKey struct{}

// WithCheckDispatchProgress binds subsequent check batches to this operation.
// A new binding isolates late callbacks from a previously canceled operation.
func WithCheckDispatchProgress(ctx context.Context) (context.Context, *CheckDispatchProgress) {
	p := &CheckDispatchProgress{monitor: checkDispatches, batches: make(map[*checkDispatchBatch]struct{}), last: time.Now()}
	return context.WithValue(ctx, dispatchProgressContextKey{}, p), p
}

func (m *checkDispatchMonitor) observe(ctx context.Context, tasks []*checkDispatch) {
	p, _ := ctx.Value(dispatchProgressContextKey{}).(*CheckDispatchProgress)
	if p == nil || len(tasks) == 0 {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	batch := tasks[0].batch
	batch.observer = p
	p.batches[batch] = struct{}{}
	p.last = time.Now()
}

func (b *checkDispatchBatch) progressed(now time.Time) {
	b.progress = now
	if b.observer != nil {
		b.observer.last = now
	}
}

// Snapshot does not query contexts, the filesystem or the job store.
func (p *CheckDispatchProgress) Snapshot(now time.Time) DispatchProgressSnapshot {
	p.monitor.mu.Lock()
	defer p.monitor.mu.Unlock()
	s := DispatchProgressSnapshot{Active: len(p.batches) != 0, LastProgress: p.last}
	for batch := range p.batches {
		waiting := 0
		for task := range batch.tasks {
			if task.started.IsZero() {
				waiting++
			} else {
				s.Overdue = s.Overdue || !now.Before(task.deadline)
			}
		}
		if waiting > 0 && batch.budget.hasCapacity() && now.Sub(batch.progress) >= checkDispatchControlBudget {
			s.Overdue = true
		}
	}
	return s
}
