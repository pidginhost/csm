package phptaintworker

import (
	"sync"
	"time"

	"github.com/pidginhost/csm/internal/queuehealth"
)

type requestQueue struct {
	mu      sync.Mutex
	pending map[*requestWork]struct{}
	losses  *queuehealth.Tracker
}

type requestWork struct {
	queue                                           *requestQueue
	queued, started, phaseDeadline, rpcDeadline     time.Time
	callerDone, rpcOutstanding, awaitingRPC, failed bool
}

func newRequestQueue() *requestQueue {
	return &requestQueue{pending: make(map[*requestWork]struct{}), losses: queuehealth.New(0, time.Minute)}
}

func (q *requestQueue) begin() *requestWork {
	w := &requestWork{queue: q, queued: time.Now()}
	q.mu.Lock()
	q.pending[w] = struct{}{}
	q.mu.Unlock()
	return w
}

func (w *requestWork) start() {
	w.queue.mu.Lock()
	w.started = time.Now()
	w.phaseDeadline = w.started.Add(time.Minute)
	w.queue.mu.Unlock()
}

func (w *requestWork) beginRPC(deadline time.Time) {
	w.queue.mu.Lock()
	w.rpcOutstanding = true
	w.awaitingRPC = true
	w.rpcDeadline, w.phaseDeadline = deadline, deadline
	w.queue.mu.Unlock()
}

func (w *requestWork) progress() {
	w.queue.mu.Lock()
	w.awaitingRPC = false
	w.phaseDeadline = time.Now().Add(time.Minute)
	w.queue.mu.Unlock()
}

func (w *requestWork) finishRPC(completed bool) {
	q := w.queue
	q.mu.Lock()
	defer q.mu.Unlock()
	w.rpcOutstanding = false
	if w.awaitingRPC {
		w.awaitingRPC = false
		w.phaseDeadline = time.Now().Add(time.Minute)
	}
	if !completed {
		w.failLocked()
	}
	w.releaseLocked()
}

func (w *requestWork) finishCaller(completed bool) {
	q := w.queue
	q.mu.Lock()
	defer q.mu.Unlock()
	w.callerDone = true
	if !completed {
		w.failLocked()
	}
	w.releaseLocked()
}

func (w *requestWork) releaseLocked() {
	// Closing the pipes normally releases the RPC goroutine. A caller that
	// already returned must not hide an operation still blocked in I/O.
	if w.callerDone && !w.rpcOutstanding {
		delete(w.queue.pending, w)
	}
}

func (w *requestWork) fail() {
	w.queue.mu.Lock()
	w.failLocked()
	w.queue.mu.Unlock()
}

func (w *requestWork) failLocked() {
	if !w.failed {
		w.failed = true
		w.queue.losses.Lose(time.Now(), 1)
	}
}

// QueueStatuses does not take the supervisor lock or inspect child processes.
func (s *Supervisor) QueueStatuses(now time.Time) map[string]queuehealth.Status {
	q := s.health
	q.mu.Lock()
	defer q.mu.Unlock()
	status := q.losses.Snapshot(now)
	status.CapacityUnavailable = true
	var waitingLate, runningLate bool
	for w := range q.pending {
		if w.started.IsZero() {
			status.Depth++
			status.LagSeconds = max(status.LagSeconds, now.Sub(w.queued).Seconds())
			waitingLate = waitingLate || now.Sub(w.queued) >= time.Minute
		} else {
			status.InFlight++
			status.ProcessingSeconds = max(status.ProcessingSeconds, now.Sub(w.started).Seconds())
			runningLate = runningLate || (!w.callerDone && !now.Before(w.phaseDeadline)) || (w.rpcOutstanding && !now.Before(w.rpcDeadline))
		}
	}
	switch {
	case waitingLate:
		status.Reason = "backlog_lag"
	case runningLate:
		status.Reason = "processing_lag"
	}
	if status.Reason != "" {
		status.Status = "degraded"
	}
	return map[string]queuehealth.Status{"requests": status}
}
