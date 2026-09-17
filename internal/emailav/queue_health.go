package emailav

import (
	"sync"
	"time"

	"github.com/pidginhost/csm/internal/queuehealth"
)

type scanQueue struct {
	mu      sync.Mutex
	pending map[*scanWork]struct{}
	losses  *queuehealth.Tracker
}

type scanWork struct {
	queue                               *scanQueue
	queued, deadline                    time.Time
	started, returned, ready, receiving time.Time
	engineDone, deliveryDone, failed    bool
}

func newScanQueue() *scanQueue {
	return &scanQueue{pending: make(map[*scanWork]struct{}), losses: queuehealth.New(0, time.Minute)}
}

func (q *scanQueue) begin(deadline time.Time) *scanWork {
	w := &scanWork{queue: q, queued: time.Now(), deadline: deadline}
	q.mu.Lock()
	q.pending[w] = struct{}{}
	q.mu.Unlock()
	return w
}

func (w *scanWork) start() {
	w.queue.mu.Lock()
	w.started = time.Now()
	w.queue.mu.Unlock()
}

func (w *scanWork) finishEngine(success bool) {
	q := w.queue
	q.mu.Lock()
	defer q.mu.Unlock()
	w.engineDone = true
	w.returned = time.Now()
	if !success {
		w.failLocked()
	}
	w.releaseLocked()
}

func (w *scanWork) publish(failed bool) {
	q := w.queue
	q.mu.Lock()
	defer q.mu.Unlock()
	w.ready = time.Now()
	if failed {
		w.failLocked()
	}
}

func (w *scanWork) received() {
	w.queue.mu.Lock()
	w.receiving = time.Now()
	w.queue.mu.Unlock()
}

func (w *scanWork) finishDelivery(success bool) {
	q := w.queue
	q.mu.Lock()
	defer q.mu.Unlock()
	if w.deliveryDone {
		return
	}
	w.deliveryDone = true
	if !success {
		w.failLocked()
	}
	w.releaseLocked()
}

func (w *scanWork) failLocked() {
	if !w.failed {
		w.failed = true
		w.queue.losses.Lose(time.Now(), 1)
	}
}

func (w *scanWork) releaseLocked() {
	// Timeout releases result delivery while Scan may still run. Conversely,
	// a returned engine can leave work in either buffered result handoff.
	if w.engineDone && w.deliveryDone {
		delete(w.queue.pending, w)
	}
}

// QueueStatuses reads memory without probing an engine or taking its locks.
func (o *Orchestrator) QueueStatuses(now time.Time) map[string]queuehealth.Status {
	q := o.health
	q.mu.Lock()
	defer q.mu.Unlock()
	s := q.losses.Snapshot(now)
	// Concurrent ScanParts calls and engines outliving their callers have no
	// fixed global admission limit, despite each result channel being bounded.
	s.CapacityUnavailable = true
	var waitingLate, runningLate bool
	for w := range q.pending {
		origin, deadline, running := w.queued, w.deadline, false
		switch {
		case !w.engineDone:
			if !w.started.IsZero() {
				origin, running = w.started, true
			}
		case !w.receiving.IsZero():
			origin, running = w.receiving, true
			deadline = origin.Add(time.Minute)
		default:
			origin = w.returned
			if !w.ready.IsZero() && w.ready.Before(origin) {
				origin = w.ready
			}
			deadline = origin.Add(time.Minute)
		}
		if running {
			s.InFlight++
			s.ProcessingSeconds = max(s.ProcessingSeconds, now.Sub(origin).Seconds())
			runningLate = runningLate || !now.Before(deadline)
		} else {
			s.Depth++
			s.LagSeconds = max(s.LagSeconds, now.Sub(origin).Seconds())
			waitingLate = waitingLate || !now.Before(deadline)
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
	return map[string]queuehealth.Status{"scans": s}
}
