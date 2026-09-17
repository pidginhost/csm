package checks

import (
	"sync"
	"time"

	"github.com/pidginhost/csm/internal/queuehealth"
)

var autoBlockQueues = newAutoBlockQueue()

type autoBlockQueueMonitor struct {
	mu                      sync.Mutex
	waiting                 map[*autoBlockStateWork]struct{}
	active                  *autoBlockStateWork
	retries                 *autoBlockRetryQueue
	cleanup                 *autoBlockCleanupQueue
	idleSince               time.Time
	waitingLoss, activeLoss *queuehealth.Tracker
}

type autoBlockStateWork struct {
	queue             *autoBlockQueueMonitor
	at                time.Time
	failed, completed bool
	readingState      bool
	retryCycle        *autoBlockRetryCycle
	cleanupCycle      *autoBlockCleanupCycle
}

func newAutoBlockQueue() *autoBlockQueueMonitor {
	return &autoBlockQueueMonitor{cleanup: newAutoBlockCleanupQueue(), retries: newAutoBlockRetryQueue(), waiting: make(map[*autoBlockStateWork]struct{}), waitingLoss: queuehealth.New(0, time.Minute), activeLoss: queuehealth.New(1, time.Minute)}
}

func (q *autoBlockQueueMonitor) acquire() *autoBlockStateWork {
	w := &autoBlockStateWork{queue: q, at: time.Now()}
	q.mu.Lock()
	if q.active == nil && len(q.waiting) == 0 {
		q.idleSince = w.at
	}
	q.waiting[w] = struct{}{}
	q.mu.Unlock()
	blockStateMu.Lock()
	q.mu.Lock()
	delete(q.waiting, w)
	q.active = w
	w.at = time.Now()
	q.mu.Unlock()
	return w
}

func (w *autoBlockStateWork) progress() {
	w.queue.mu.Lock()
	w.at = time.Now()
	w.queue.mu.Unlock()
}

func (w *autoBlockStateWork) failLocked() {
	if !w.failed {
		w.failed = true
		w.queue.activeLoss.Lose(time.Now(), 1)
	}
}

func (w *autoBlockStateWork) observe(err error) {
	if err == nil {
		return
	}
	w.queue.mu.Lock()
	w.failLocked()
	w.queue.mu.Unlock()
}

func (w *autoBlockStateWork) complete() {
	w.queue.mu.Lock()
	w.completed = true
	w.queue.mu.Unlock()
}

func (w *autoBlockStateWork) finish() {
	q := w.queue
	q.mu.Lock()
	defer q.mu.Unlock()
	// Release the real slot with its owner, including when the accounting
	// below fails. A successor must not publish over a callback whose cleanup
	// is still running, and a failure must not strand every later block.
	defer blockStateMu.Unlock()
	if !w.completed {
		w.failLocked()
	}
	w.finishRetriesLocked()
	w.finishCleanupLocked()
	q.active = nil
	q.idleSince = time.Now()
}

// AutoBlockQueueStatuses reads queue memory without waiting for the state mutex,
// filesystem, firewall or database. A batch is timed by operation progress.
func AutoBlockQueueStatuses(now time.Time) map[string]queuehealth.Status {
	q := autoBlockQueues
	q.mu.Lock()
	defer q.mu.Unlock()
	waiting := q.waitingLoss.Snapshot(now)
	waiting.CapacityUnavailable = true
	active := q.activeLoss.Snapshot(now)
	active.LagBasis = "operation_progress"
	stalled := q.active == nil && !q.idleSince.IsZero() && now.Sub(q.idleSince) >= time.Minute
	if w := q.active; w != nil {
		active.InFlight = 1
		active.ProcessingSeconds = max(0, now.Sub(w.at).Seconds())
		if active.ProcessingSeconds >= time.Minute.Seconds() {
			active.Status, active.Reason = "degraded", "processing_lag"
			stalled = true
		}
	}
	for w := range q.waiting {
		waiting.Depth++
		waiting.LagSeconds = max(waiting.LagSeconds, now.Sub(w.at).Seconds())
		if stalled {
			waiting.Status, waiting.Reason = "degraded", "backlog_lag"
		}
	}
	pending, candidates := q.retries.statuses(now, q.active)
	return map[string]queuehealth.Status{"waiting": waiting, "active": active, "pending": pending, "candidates": candidates, "cleanup": q.cleanup.status(now, q.active)}
}
