// Package queuehealth measures waiting, running and lost work independently
// of the channel that carries findings about a protection failure.
package queuehealth

import (
	"sync"
	"time"
)

const (
	dropWindow    = time.Minute
	fullWindow    = 30 * time.Second
	dropThreshold = 3
)

// Status is the queue evidence carried by status, the API and doctor.
// LagSeconds measures the oldest waiting item unless LagBasis names another
// measurement. ProcessingSeconds measures
// the oldest running item, so an empty queue cannot conceal a stuck worker.
type Status struct {
	Status              string  `json:"status"`
	Reason              string  `json:"reason,omitempty"`
	Depth               int     `json:"depth"`
	DepthUnit           string  `json:"depth_unit,omitempty"`
	DepthUnavailable    bool    `json:"depth_unavailable,omitempty"`
	LagBasis            string  `json:"lag_basis,omitempty"`
	Capacity            int     `json:"capacity"`
	CapacityUnavailable bool    `json:"capacity_unavailable,omitempty"`
	InFlight            int     `json:"in_flight"`
	DroppedTotal        uint64  `json:"dropped_total"`
	DroppedLowerBound   bool    `json:"dropped_lower_bound,omitempty"`
	RecentDrops         uint64  `json:"recent_drops"`
	LagSeconds          float64 `json:"lag_seconds"`
	ProcessingSeconds   float64 `json:"processing_seconds"`
}

type work struct {
	queued  time.Time
	started time.Time
}

type dropBucket struct {
	second int64
	count  uint64
}

// Tracker accounts for a bounded queue and its workers. Every Begin must
// end in Finish or Reject, including cancellation and panic paths. Tracking
// starts before a send so a fast consumer cannot finish an unrecorded item.
// Its retained work is bounded by the queue and the producer/worker counts.
type Tracker struct {
	mu             sync.Mutex
	capacity       int
	maxLag         time.Duration
	sharedCapacity bool
	next           uint64
	pending        map[uint64]work
	waiting        int
	fullSince      time.Time
	dropped        uint64
	drops          [60]dropBucket
}

func New(capacity int, maxLag time.Duration) *Tracker {
	return &Tracker{capacity: capacity, maxLag: maxLag, pending: make(map[uint64]work)}
}

// NewSharedCapacity measures queues whose running work still occupies
// admission slots. Ordinary channels free those slots when a consumer reads.
func NewSharedCapacity(capacity int, maxLag time.Duration) *Tracker {
	q := New(capacity, maxLag)
	q.sharedCapacity = true
	return q
}

// Ticket follows one item from enqueue through processing. A zero ticket
// represents synchronous work that never entered a queue.
type Ticket struct {
	tracker *Tracker
	id      uint64
}

func (q *Tracker) Begin(now time.Time) Ticket {
	return q.BeginAt(now, now)
}

// BeginAt sets the waiting-age origin independently of admission. Earlier
// delays must not backdate saturation; a future origin defers lag until the
// work is eligible to run.
func (q *Tracker) BeginAt(queuedAt, now time.Time) Ticket {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.next++
	q.pending[q.next] = work{queued: queuedAt}
	q.waiting++
	q.updateFull(now)
	return Ticket{tracker: q, id: q.next}
}

func (t Ticket) Start(now time.Time) {
	if t.tracker == nil {
		return
	}
	q := t.tracker
	q.mu.Lock()
	defer q.mu.Unlock()
	w := q.pending[t.id]
	w.started = now
	q.pending[t.id] = w
	q.waiting--
	q.updateFull(now)
}

// Requeue returns a running item to waiting without resetting its admission
// time. Repeated attempts must not conceal a backlog that never completes.
func (t Ticket) Requeue(now time.Time) {
	if t.tracker == nil {
		return
	}
	q := t.tracker
	q.mu.Lock()
	defer q.mu.Unlock()
	w := q.pending[t.id]
	w.started = time.Time{}
	q.pending[t.id] = w
	q.waiting++
	q.updateFull(now)
}

// RetainQueuedAt preserves earlier eligibility when observations coalesce.
// A later observation must never postpone work that was already overdue.
func (t Ticket) RetainQueuedAt(queuedAt time.Time) {
	if t.tracker == nil {
		return
	}
	q := t.tracker
	q.mu.Lock()
	defer q.mu.Unlock()
	w := q.pending[t.id]
	if queuedAt.Before(w.queued) {
		w.queued = queuedAt
		q.pending[t.id] = w
	}
}

// MergeRunning absorbs a distinct running ticket on the same tracker into
// this waiting ticket. The caller retains only this ticket. Keeping the
// older age and completing the running ticket atomically avoids inventing
// an available waiting slot while coalescing a retry with new work.
func (t Ticket) MergeRunning(running Ticket, now time.Time) {
	if t.tracker == nil {
		return
	}
	q := t.tracker
	q.mu.Lock()
	defer q.mu.Unlock()
	w := q.pending[t.id]
	if earlier := q.pending[running.id].queued; earlier.Before(w.queued) {
		w.queued = earlier
	}
	q.pending[t.id] = w
	q.finish(running.id, now)
}

func (t Ticket) Finish(now time.Time) {
	if t.tracker == nil {
		return
	}
	q := t.tracker
	q.mu.Lock()
	defer q.mu.Unlock()
	q.finish(t.id, now)
}

func (t Ticket) Reject(now time.Time) {
	if t.tracker == nil {
		return
	}
	q := t.tracker
	q.mu.Lock()
	defer q.mu.Unlock()
	q.finish(t.id, now)
	q.lose(now, 1)
}

func (q *Tracker) finish(id uint64, now time.Time) {
	if q.pending[id].started.IsZero() {
		q.waiting--
	}
	delete(q.pending, id)
	q.updateFull(now)
}

func (q *Tracker) updateFull(now time.Time) {
	occupied := q.waiting
	if q.sharedCapacity {
		occupied = len(q.pending)
	}
	if q.capacity > 0 && occupied >= q.capacity {
		if q.fullSince.IsZero() {
			q.fullSince = now
		}
	} else {
		q.fullSince = time.Time{}
	}
}

// Lose records upstream loss for which no userspace work item exists, such
// as a kernel overflow. The cumulative count is never drained by a reporter.
func (q *Tracker) Lose(now time.Time, count uint64) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.lose(now, count)
}

func (q *Tracker) lose(now time.Time, count uint64) {
	q.dropped += count
	second := now.Unix()
	b := &q.drops[uint64(second)%uint64(len(q.drops))] // #nosec G115 -- modulo index is bounded even for a pre-epoch clock
	if b.second != second {
		*b = dropBucket{second: second}
	}
	b.count += count
}

func (q *Tracker) Snapshot(now time.Time) Status {
	q.mu.Lock()
	defer q.mu.Unlock()
	s := Status{Status: "ok", Capacity: q.capacity, Depth: q.waiting, InFlight: len(q.pending) - q.waiting, DroppedTotal: q.dropped}
	for _, w := range q.pending {
		if w.started.IsZero() {
			s.LagSeconds = max(s.LagSeconds, now.Sub(w.queued).Seconds())
		} else {
			s.ProcessingSeconds = max(s.ProcessingSeconds, now.Sub(w.started).Seconds())
		}
	}
	second := now.Unix()
	for _, b := range q.drops {
		if b.second <= second && second-b.second < int64(dropWindow/time.Second) {
			s.RecentDrops += b.count
		}
	}
	switch {
	case s.LagSeconds >= q.maxLag.Seconds():
		s.Reason = "backlog_lag"
	case s.ProcessingSeconds >= q.maxLag.Seconds():
		s.Reason = "processing_lag"
	case !q.fullSince.IsZero() && now.Sub(q.fullSince) >= fullWindow:
		s.Reason = "queue_full"
	case s.RecentDrops >= dropThreshold:
		s.Reason = "dropped_work"
	}
	if s.Reason != "" {
		s.Status = "degraded"
	}
	return s
}
