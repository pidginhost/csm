package daemon

import (
	"sync"
	"time"

	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/queuehealth"
)

const scanJobControlBudget = time.Minute

type scanJobHealth struct {
	mu        sync.Mutex
	pending   map[*scanJobWork]struct{}
	losses    *queuehealth.Tracker
	admission *queuehealth.Tracker
	progress  time.Time
	fullSince time.Time
}

type scanJobWork struct {
	owner    *scanJobHealth
	checks   func(time.Time) checks.DispatchProgressSnapshot
	started  time.Time
	progress time.Time
	failed   bool
}

func newScanJobHealth() *scanJobHealth {
	return &scanJobHealth{
		pending:   make(map[*scanJobWork]struct{}),
		losses:    queuehealth.New(0, scanJobControlBudget),
		admission: queuehealth.New(0, scanJobControlBudget),
	}
}

func (h *scanJobHealth) begin(progress func(time.Time) checks.DispatchProgressSnapshot) *scanJobWork {
	h.mu.Lock()
	defer h.mu.Unlock()
	now := time.Now()
	if len(h.pending) == 0 {
		h.progress = now
	}
	w := &scanJobWork{owner: h, checks: progress, progress: now}
	h.pending[w] = struct{}{}
	h.updateFull(now)
	return w
}

func (h *scanJobHealth) updateFull(now time.Time) {
	waiting := 0
	for w := range h.pending {
		if w.started.IsZero() {
			waiting++
		}
	}
	if waiting >= scanJobQueueDepth {
		if h.fullSince.IsZero() {
			h.fullSince = now
		}
	} else {
		h.fullSince = time.Time{}
	}
}

func (w *scanJobWork) progressed() {
	w.owner.mu.Lock()
	defer w.owner.mu.Unlock()
	w.progress = time.Now()
	w.owner.progress = w.progress
}

func (w *scanJobWork) fail() {
	w.owner.mu.Lock()
	defer w.owner.mu.Unlock()
	w.failLocked(time.Now())
}

func (w *scanJobWork) failLocked(now time.Time) {
	if !w.failed {
		w.failed = true
		w.owner.losses.Lose(now, 1)
	}
}

func (w *scanJobWork) finish(completed bool) {
	h := w.owner
	h.mu.Lock()
	defer h.mu.Unlock()
	now := time.Now()
	if !completed {
		w.failLocked(now)
	}
	delete(h.pending, w)
	if !w.started.IsZero() {
		h.progress = now
	}
	h.updateFull(now)
}

func (w *scanJobWork) run(fn func()) {
	h := w.owner
	h.mu.Lock()
	w.started = time.Now()
	w.progress = w.started
	h.progress = w.started
	h.updateFull(w.started)
	h.mu.Unlock()
	completed := false
	defer func() { w.finish(completed) }()
	fn()
	completed = true
}

func (h *scanJobHealth) snapshot(now time.Time) queuehealth.Status {
	h.mu.Lock()
	defer h.mu.Unlock()
	s := h.losses.Snapshot(now)
	s.Capacity = scanJobQueueDepth
	s.LagBasis = "consumer_progress"
	progress := h.progress
	var overdue bool
	for w := range h.pending {
		if w.started.IsZero() {
			s.Depth++
			continue
		}
		s.InFlight++
		s.ProcessingSeconds = max(s.ProcessingSeconds, now.Sub(w.started).Seconds())
		child := w.checks(now)
		latest := w.progress
		if child.LastProgress.After(latest) {
			latest = child.LastProgress
		}
		if latest.After(progress) {
			progress = latest
		}
		if child.Active {
			overdue = overdue || child.Overdue
		} else {
			overdue = overdue || now.Sub(latest) >= scanJobControlBudget
		}
	}
	if s.Depth > 0 {
		s.LagSeconds = max(0, now.Sub(progress).Seconds())
	}
	switch {
	case overdue:
		s.Reason = "processing_lag"
	case s.Depth > 0 && s.InFlight == 0 && now.Sub(progress) >= scanJobControlBudget:
		s.Reason = "backlog_lag"
	case !h.fullSince.IsZero() && now.Sub(h.fullSince) >= 30*time.Second:
		s.Reason = "queue_full"
	}
	if s.Reason != "" {
		s.Status = "degraded"
	}
	return s
}

// QueueStatuses retains work through persistence and worker cleanup. It never
// takes the cancellation lock or asks the store for progress.
func (m *ScanJobManager) QueueStatuses(now time.Time) map[string]queuehealth.Status {
	admission := m.health.admission.Snapshot(now)
	admission.CapacityUnavailable = true
	return map[string]queuehealth.Status{"jobs": m.health.snapshot(now), "admission": admission}
}
