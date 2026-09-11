//go:build linux && bpf

package bpf

import (
	"sync"
	"time"

	"github.com/pidginhost/csm/internal/queuehealth"
)

// This layout is shared with csm_queue_stats in the BPF programs.
type kernelCounts struct {
	Lost      uint64
	Submitted uint64
}

type ringMeasurement interface {
	AvailableBytes() int
	BufferSize() int
}

type kernelQueue struct {
	mu          sync.Mutex
	ring        ringMeasurement
	counters    func() (kernelCounts, error)
	health      *queuehealth.Sampled
	unmeasured  queuehealth.Dwell
	lost        uint64
	closed      bool
	finished    bool
	unavailable bool
}

func newKernelQueue(ring ringMeasurement, counters func() (kernelCounts, error)) *kernelQueue {
	return &kernelQueue{ring: ring, counters: counters, health: queuehealth.NewSampled(ring.BufferSize(), "bytes", time.Minute)}
}

func (q *kernelQueue) readCounters(now func() time.Time) (kernelCounts, bool) {
	counts, err := q.counters()
	q.unavailable = err != nil || counts.Lost < q.lost
	if q.unavailable {
		return counts, false
	}
	q.health.Lose(now(), counts.Lost-q.lost)
	q.lost = counts.Lost
	return counts, true
}

func (q *kernelQueue) snapshot(now func() time.Time, consumed func() uint64) queuehealth.Status {
	q.mu.Lock()
	defer q.mu.Unlock()
	invalidDepth := false
	if !q.finished {
		q.readCounters(now)
		if !q.closed {
			depth := q.ring.AvailableBytes()
			// Producer and consumer positions are loaded separately. Concurrent
			// progress can make their difference fall outside the real ring.
			invalidDepth = depth < 0 || depth > q.ring.BufferSize()
			if !invalidDepth {
				q.health.Observe(now(), depth, consumed())
			}
		}
	}
	at := now()
	s := q.health.Snapshot(at)
	s.DroppedLowerBound = q.finished
	if invalidDepth {
		s.Depth, s.LagSeconds = 0, 0
		s.DepthUnavailable, s.LagBasis = true, "unavailable"
	}
	unmeasured := q.unmeasured.Held(at, q.unavailable || invalidDepth, queuehealth.MeasurementWindow)
	switch {
	case q.closed && !q.finished:
		// A reader that stopped explains every later measurement, so it is
		// reported instead of the artefacts it causes.
		s.Depth, s.LagSeconds = 0, 0
		s.DepthUnavailable, s.LagBasis = true, "unavailable"
		s.Status, s.Reason = "degraded", "reader_stopped"
	case q.finished && q.unavailable:
		// The final sample cannot be retried, so it degrades without a dwell.
		s.Status, s.Reason = "degraded", "measurement_unavailable"
	case unmeasured:
		s.Status, s.Reason = "degraded", "measurement_unavailable"
	}
	return s
}

// AvailableBytes dereferences cilium's mmap without taking its close lock.
// Serialize our health reads with unmapping without holding the blocking Read
// lock, which would prevent health polling when no kernel events arrive.
func (q *kernelQueue) closeRing(closeReader func() error) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	err := closeReader()
	q.closed = true
	return err
}

// The owner calls finish after detaching producers and joining the reader,
// while the counter map is still alive. Only then are submitted-minus-consumed
// records known to be abandoned. Detachment does not wait for every kernel
// callback, so the retained final sample is explicitly a lower bound.
func (q *kernelQueue) finish(now func() time.Time, consumed uint64) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.finished {
		return
	}
	if counts, ok := q.readCounters(now); ok {
		if counts.Submitted < consumed {
			q.unavailable = true
		} else {
			q.health.Lose(now(), counts.Submitted-consumed)
		}
	}
	q.health.Observe(now(), 0, consumed)
	q.finished = true
}
