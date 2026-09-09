package queuehealth

import (
	"sync"
	"time"
)

// Sampled measures opaque queues whose entries cannot carry tickets. Its lag
// is time since observed consumer progress while work remains, not the age of
// an unseen event. Owners sample depth and a monotonic consumption counter
// together; observing new arrivals alone must not reset a stalled consumer.
type Sampled struct {
	mu           sync.Mutex
	capacity     int
	unit         string
	maxLag       time.Duration
	depth        int
	progress     uint64
	stalledSince time.Time
	fullSince    time.Time
	losses       *Tracker
}

func NewSampled(capacity int, unit string, maxLag time.Duration) *Sampled {
	return &Sampled{capacity: capacity, unit: unit, maxLag: maxLag, losses: New(0, maxLag)}
}

func (q *Sampled) Observe(now time.Time, depth int, progress uint64) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if depth == 0 {
		q.stalledSince = time.Time{}
	} else if q.stalledSince.IsZero() || progress != q.progress {
		q.stalledSince = now
	}
	if q.capacity > 0 && depth >= q.capacity {
		if q.fullSince.IsZero() {
			q.fullSince = now
		}
	} else {
		q.fullSince = time.Time{}
	}
	q.depth, q.progress = depth, progress
}

func (q *Sampled) Lose(now time.Time, count uint64) { q.losses.Lose(now, count) }

func (q *Sampled) Snapshot(now time.Time) Status {
	q.mu.Lock()
	defer q.mu.Unlock()
	s := q.losses.Snapshot(now)
	s.Depth, s.Capacity, s.DepthUnit = q.depth, q.capacity, q.unit
	s.LagBasis = "consumer_progress"
	if !q.stalledSince.IsZero() {
		s.LagSeconds = max(0, now.Sub(q.stalledSince).Seconds())
	}
	switch {
	case s.LagSeconds >= q.maxLag.Seconds():
		s.Reason = "consumer_stalled"
	case !q.fullSince.IsZero() && now.Sub(q.fullSince) >= fullWindow:
		s.Reason = "queue_full"
	}
	if s.Reason != "" {
		s.Status = "degraded"
	}
	return s
}
