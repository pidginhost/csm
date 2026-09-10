package checks

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/queuehealth"
)

var fileIndexQueues = newFileIndexQueue()

type fileIndexQueueMonitor struct {
	mu                      sync.Mutex
	waiting                 map[*fileIndexWork]struct{}
	active                  *fileIndexWork
	idleSince               time.Time
	waitingLoss, activeLoss *queuehealth.Tracker
}

type fileIndexWork struct {
	queue                           *fileIndexQueueMonitor
	at, deadline, executionDeadline time.Time
	running, failed                 bool
}

func newFileIndexQueue() *fileIndexQueueMonitor {
	return &fileIndexQueueMonitor{
		waiting:     make(map[*fileIndexWork]struct{}),
		waitingLoss: queuehealth.New(0, time.Minute),
		activeLoss:  queuehealth.New(1, time.Minute),
	}
}

func (q *fileIndexQueueMonitor) run(ctx context.Context, fn func(*fileIndexWork) []alert.Finding) []alert.Finding {
	if ctx.Err() != nil {
		return nil
	}
	now := time.Now()
	budget := timeoutFor("file_index")
	parent, hasParent := ctx.Deadline()
	deadline := now.Add(budget)
	if hasParent && parent.Before(deadline) {
		deadline = parent
	}
	w := &fileIndexWork{queue: q, at: now, deadline: deadline}
	q.mu.Lock()
	if q.active == nil && len(q.waiting) == 0 {
		q.idleSince = now
	}
	q.waiting[w] = struct{}{}
	q.mu.Unlock()
	completed := false
	defer func() { w.finish(completed) }()
	select {
	case fileIndexLiveScanGate <- struct{}{}:
		now = time.Now()
		executionDeadline := now.Add(budget)
		if hasParent && parent.Before(executionDeadline) {
			executionDeadline = parent
		}
		q.mu.Lock()
		delete(q.waiting, w)
		q.active = w
		q.idleSince = time.Time{}
		w.running = true
		w.at = now
		w.deadline = now.Add(time.Minute)
		w.executionDeadline = executionDeadline
		q.mu.Unlock()
	case <-ctx.Done():
		w.withdraw(ctx.Err())
		completed = true
		return nil
	}
	findings := fn(w)
	completed = true
	return findings
}

func (w *fileIndexWork) execution() {
	w.queue.mu.Lock()
	w.at = time.Now()
	w.deadline = w.executionDeadline
	w.queue.mu.Unlock()
}

func (w *fileIndexWork) local() {
	w.queue.mu.Lock()
	w.at = time.Now()
	w.deadline = w.at.Add(time.Minute)
	w.queue.mu.Unlock()
}

func (w *fileIndexWork) failLocked() {
	if w.failed {
		return
	}
	w.failed = true
	losses := w.queue.waitingLoss
	if w.running {
		losses = w.queue.activeLoss
	}
	losses.Lose(time.Now(), 1)
}

func (w *fileIndexWork) fail() {
	w.queue.mu.Lock()
	w.failLocked()
	w.queue.mu.Unlock()
}

func (w *fileIndexWork) observe(err error) {
	if err != nil {
		w.fail()
	}
}

func (w *fileIndexWork) withdraw(err error) {
	if errors.Is(err, context.Canceled) {
		return
	}
	w.queue.mu.Lock()
	w.failLocked()
	w.queue.mu.Unlock()
}

func (w *fileIndexWork) finish(completed bool) {
	q := w.queue
	q.mu.Lock()
	defer q.mu.Unlock()
	if !completed {
		w.failLocked()
	}
	if w.running {
		q.active = nil
		q.idleSince = time.Now()
		// The scan owns this token. Release its health owner and token under
		// one lock so its successor cannot publish before this owner leaves.
		<-fileIndexLiveScanGate
	} else {
		delete(q.waiting, w)
	}
}

// FileIndexQueueStatuses reads memory without waiting for a scan or filesystem.
func FileIndexQueueStatuses(now time.Time) map[string]queuehealth.Status {
	q := fileIndexQueues
	q.mu.Lock()
	defer q.mu.Unlock()
	waiting := q.waitingLoss.Snapshot(now)
	waiting.CapacityUnavailable = true
	active := q.activeLoss.Snapshot(now)
	for w := range q.waiting {
		waiting.Depth++
		waiting.LagSeconds = max(waiting.LagSeconds, now.Sub(w.at).Seconds())
		if !now.Before(w.deadline) || (q.active == nil && now.Sub(q.idleSince) >= time.Minute) {
			waiting.Status, waiting.Reason = "degraded", "backlog_lag"
		}
	}
	if w := q.active; w != nil {
		active.InFlight = 1
		active.ProcessingSeconds = max(0, now.Sub(w.at).Seconds())
		if !now.Before(w.deadline) {
			active.Status, active.Reason = "degraded", "processing_lag"
		}
	}
	return map[string]queuehealth.Status{"waiting": waiting, "active": active}
}
