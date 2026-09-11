package checks

import (
	"context"
	"sync"
	"time"

	"github.com/pidginhost/csm/internal/queuehealth"
)

var reputationQueries = newReputationQueue()

type reputationQueueMonitor struct {
	mu      sync.Mutex
	pending map[*reputationQueryWork]struct{}
	losses  *queuehealth.Tracker
}

type reputationQueryBatch struct {
	consumer *reputationQueryWork // guarded by the queue mutex
}

type reputationQueryWork struct {
	batch                                                  *reputationQueryBatch
	queue                                                  *reputationQueueMonitor
	at, deadline                                           time.Time
	running, queryStarted, queryDone, deliveryDone, failed bool
}

func newReputationQueue() *reputationQueueMonitor {
	return &reputationQueueMonitor{pending: make(map[*reputationQueryWork]struct{}), losses: queuehealth.New(0, time.Minute)}
}

func (q *reputationQueueMonitor) begin(batch *reputationQueryBatch) *reputationQueryWork {
	now := time.Now()
	w := &reputationQueryWork{queue: q, batch: batch, at: now, deadline: now.Add(time.Minute)}
	q.mu.Lock()
	q.pending[w] = struct{}{}
	q.mu.Unlock()
	return w
}

func (w *reputationQueryWork) moveLocked(running bool, budget time.Duration) {
	w.running = running
	w.at = time.Now()
	w.deadline = w.at.Add(budget)
}

func (w *reputationQueryWork) start(budget time.Duration) {
	w.queue.mu.Lock()
	w.queryStarted = true
	w.moveLocked(true, budget)
	w.queue.mu.Unlock()
}

func (w *reputationQueryWork) failLocked() {
	if !w.failed {
		w.failed = true
		w.queue.losses.Lose(time.Now(), 1)
	}
}

func (w *reputationQueryWork) fail() {
	w.queue.mu.Lock()
	w.failLocked()
	w.queue.mu.Unlock()
}

func (w *reputationQueryWork) cleanup(err error) {
	// Protocol calls outside the worker pool have no queued delivery owner.
	if w == nil {
		return
	}
	failed := err != nil && !abuseQuotaError(err)
	w.queue.mu.Lock()
	if failed {
		w.failLocked()
	}
	w.moveLocked(true, time.Minute)
	w.queue.mu.Unlock()
}

func (w *reputationQueryWork) returned(completed bool) {
	q := w.queue
	q.mu.Lock()
	defer q.mu.Unlock()
	if !completed {
		w.failLocked()
	}
	w.queryDone = true
	w.moveLocked(false, time.Minute)
	w.releaseLocked()
}

func (w *reputationQueryWork) phase(running bool) {
	w.queue.mu.Lock()
	w.moveLocked(running, time.Minute)
	if running {
		w.batch.consumer = w
	} else if w.batch.consumer == w {
		w.batch.consumer = nil
	}
	w.queue.mu.Unlock()
}

func (w *reputationQueryWork) consuming(ctx context.Context, budget time.Duration) {
	deadline := time.Now().Add(budget)
	if parent, ok := ctx.Deadline(); ok && parent.Before(deadline) {
		deadline = parent
	}
	w.queue.mu.Lock()
	w.moveLocked(true, budget)
	w.deadline = deadline
	w.batch.consumer = w
	w.queue.mu.Unlock()
}

func (w *reputationQueryWork) finish(success bool) {
	q := w.queue
	q.mu.Lock()
	defer q.mu.Unlock()
	if w.deliveryDone {
		return
	}
	w.deliveryDone = true
	if w.batch.consumer == w {
		w.batch.consumer = nil
	}
	if !success {
		w.failLocked()
	}
	// Dispatch can end before a worker starts. Already running HTTP keeps its
	// separate owner until response cleanup and result publication finish.
	if !w.queryStarted {
		w.queryDone = true
	}
	w.releaseLocked()
}

func (w *reputationQueryWork) releaseLocked() {
	if w.queryDone && w.deliveryDone {
		delete(w.queue.pending, w)
	}
}

// ReputationQueueStatus reads memory only, including queries outliving a check.
func ReputationQueueStatus(now time.Time) queuehealth.Status {
	q := reputationQueries
	q.mu.Lock()
	defer q.mu.Unlock()
	s := q.losses.Snapshot(now)
	s.CapacityUnavailable = true
	var waitingLate, runningLate bool
	for w := range q.pending {
		if w.running {
			s.InFlight++
			s.ProcessingSeconds = max(s.ProcessingSeconds, now.Sub(w.at).Seconds())
			runningLate = runningLate || !now.Before(w.deadline)
		} else {
			s.Depth++
			s.LagSeconds = max(s.LagSeconds, now.Sub(w.at).Seconds())
			// A result waiting behind its own batch consumer follows that
			// consumer's deadline. Another batch cannot lend it progress.
			waitingLate = waitingLate || ((!w.queryDone || w.batch.consumer == nil) && !now.Before(w.deadline))
		}
	}
	switch {
	case waitingLate:
		s.Reason = "backlog_lag"
	case runningLate:
		s.Reason = "processing_lag"
	}
	if s.Reason != "" {
		s.Status = "degraded"
	}
	return s
}
