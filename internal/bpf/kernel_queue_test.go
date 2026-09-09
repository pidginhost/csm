//go:build linux && bpf

package bpf

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/queuehealth"
)

type measuredRing struct {
	bytes  int
	closed bool
}

func (r *measuredRing) AvailableBytes() int {
	if r.closed {
		panic("read from unmapped ring")
	}
	return r.bytes
}
func (r *measuredRing) BufferSize() int { return 4096 }

func TestKernelQueueSeparatesReservationLossAndReaderProgress(t *testing.T) {
	now := time.Unix(1000, 0)
	ring := &measuredRing{bytes: 1024}
	counters := kernelCounts{Lost: 3, Submitted: 20}
	q := newKernelQueue(ring, func() (kernelCounts, error) { return counters, nil })
	got := kernelQueueSnapshot(q, now, 4)
	if got.Depth != 1024 || got.Capacity != 4096 || got.DepthUnit != "bytes" || got.LagBasis != "consumer_progress" || got.DroppedTotal != 3 || got.RecentDrops != 3 || got.Reason != "dropped_work" {
		t.Fatalf("kernel measurements absent or confused with decoded delivery: %+v", got)
	}
	got = kernelQueueSnapshot(q, now.Add(61*time.Second), 4)
	if got.LagSeconds != 61 || got.Reason != "consumer_stalled" || got.DroppedTotal != 3 || got.RecentDrops != 0 {
		t.Fatalf("stalled reader or cumulative loss was concealed: %+v", got)
	}
	ring.bytes = 512
	got = kernelQueueSnapshot(q, now.Add(62*time.Second), 8)
	if got.LagSeconds != 0 || got.Status != "ok" || got.Depth != 512 || got.DroppedTotal != 3 {
		t.Fatalf("reader progress did not recover independently of old losses: %+v", got)
	}
}

func TestKernelQueueShutdownCountsOnlyUnreadSubmittedEvents(t *testing.T) {
	now := time.Unix(1000, 0)
	ring := &measuredRing{bytes: 512}
	counters := kernelCounts{Lost: 3, Submitted: 20}
	q := newKernelQueue(ring, func() (kernelCounts, error) {
		return counters, nil
	})
	kernelQueueSnapshot(q, now, 10)
	if err := q.closeRing(func() error { ring.closed = true; return nil }); err != nil {
		t.Fatal(err)
	}
	got := kernelQueueSnapshot(q, now.Add(time.Second), 10)
	if !got.DepthUnavailable || got.Reason != "reader_stopped" || got.LagBasis != "unavailable" {
		t.Fatalf("unmapped ring exposed invented live occupancy: %+v", got)
	}
	// The owner detaches producers after context cancellation. Late kernel
	// submissions and already-read records must both enter final accounting.
	counters = kernelCounts{Lost: 5, Submitted: 23}
	finishKernelQueue(q, now.Add(2*time.Second), 12)
	finishKernelQueue(q, now.Add(3*time.Second), 12)
	got = kernelQueueSnapshot(q, now.Add(3*time.Second), 12)
	if got.Depth != 0 || got.DepthUnavailable || got.DroppedTotal != 16 || got.RecentDrops != 16 || got.LagSeconds != 0 {
		t.Fatalf("shutdown lost or duplicated reservation failures and eleven unread records: %+v", got)
	}
	counters = kernelCounts{Lost: 999, Submitted: 999}
	if got := kernelQueueSnapshot(q, now.Add(time.Minute*2), 12); got.DroppedTotal != 16 || got.Status != "ok" {
		t.Fatalf("finished queue kept reading a released counter map: %+v", got)
	}
}

func TestKernelQueueCounterFailureDoesNotClaimHealth(t *testing.T) {
	now := time.Unix(1000, 0)
	ring := &measuredRing{bytes: 64}
	failed := true
	q := newKernelQueue(ring, func() (kernelCounts, error) {
		if failed {
			return kernelCounts{}, errors.New("map unavailable")
		}
		return kernelCounts{Lost: 2, Submitted: 4}, nil
	})
	if got := kernelQueueSnapshot(q, now, 0); got.Status != "degraded" || got.Reason != "measurement_unavailable" || got.Depth != 64 {
		t.Fatalf("missing counter evidence reported healthy: %+v", got)
	}
	failed = false
	if got := kernelQueueSnapshot(q, now.Add(time.Second), 1); got.Status != "ok" || got.DroppedTotal != 2 {
		t.Fatalf("counter recovery hid losses or retained the outage: %+v", got)
	}
	failed = true
	if err := q.closeRing(func() error { ring.closed = true; return nil }); err != nil {
		t.Fatal(err)
	}
	finishKernelQueue(q, now.Add(2*time.Second), 1)
	failed = false
	if got := kernelQueueSnapshot(q, now.Add(time.Hour), 1); got.Status != "degraded" || got.Reason != "measurement_unavailable" || got.DroppedTotal != 2 {
		t.Fatalf("failed final accounting was silently recovered: %+v", got)
	}
}

func TestKernelQueueSnapshotCannotReadDuringUnmap(t *testing.T) {
	ring := &measuredRing{bytes: 64}
	q := newKernelQueue(ring, func() (kernelCounts, error) { return kernelCounts{Submitted: 1}, nil })
	var readers sync.WaitGroup
	for range 4 {
		readers.Go(func() {
			for range 1000 {
				got := kernelQueueSnapshot(q, time.Now(), 0)
				if got.Capacity != 4096 || got.DepthUnit != "bytes" {
					t.Errorf("bad snapshot: %+v", got)
					return
				}
			}
		})
	}
	if err := q.closeRing(func() error { ring.closed = true; return nil }); err != nil {
		t.Fatal(err)
	}
	finishKernelQueue(q, time.Now(), 0)
	readers.Wait()
	if got := kernelQueueSnapshot(q, time.Now(), 0); got.Depth != 0 || got.DroppedTotal != 1 {
		t.Fatalf("concurrent shutdown lost retained work: %+v", got)
	}
}

func TestKernelQueueFinalCounterSnapshotIsALowerBound(t *testing.T) {
	ring := &measuredRing{}
	q := newKernelQueue(ring, func() (kernelCounts, error) { return kernelCounts{Lost: 3, Submitted: 5}, nil })
	if got := kernelQueueSnapshot(q, time.Now(), 2); got.DroppedLowerBound {
		t.Fatalf("live reservation counter unexpectedly marked incomplete: %+v", got)
	}
	if err := q.closeRing(func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	finishKernelQueue(q, time.Now(), 2)
	got := kernelQueueSnapshot(q, time.Now(), 2)
	if !got.DroppedLowerBound || got.DroppedTotal != 6 {
		t.Fatalf("detach cannot prove that all kernel callbacks finished before the last snapshot: %+v", got)
	}
}

func TestKernelQueueRejectsIncoherentOccupancySamples(t *testing.T) {
	for _, depth := range []int{-64, 4160} {
		ring := &measuredRing{bytes: depth}
		q := newKernelQueue(ring, func() (kernelCounts, error) { return kernelCounts{Lost: 2}, nil })
		got := kernelQueueSnapshot(q, time.Now(), 0)
		if got.Status != "degraded" || got.Reason != "measurement_unavailable" || !got.DepthUnavailable || got.Depth != 0 || got.LagBasis != "unavailable" || got.DroppedTotal != 2 {
			t.Fatalf("incoherent occupancy %d was exposed as a valid queue: %+v", depth, got)
		}
		ring.bytes = 64
		if got := kernelQueueSnapshot(q, time.Now(), 1); got.Status != "ok" || got.DepthUnavailable || got.Depth != 64 || got.LagBasis != "consumer_progress" || got.DroppedTotal != 2 {
			t.Fatalf("valid occupancy did not recover while retaining losses: %+v", got)
		}
	}
}

func TestKernelQueueDoesNotBackdateFreshMeasurement(t *testing.T) {
	now := time.Unix(1000, 0)
	ring := &measuredRing{bytes: 64}
	calls := 0
	q := newKernelQueue(ring, func() (kernelCounts, error) {
		calls++
		if calls == 1 {
			now = now.Add(61 * time.Second)
		}
		return kernelCounts{}, nil
	})
	q.snapshot(func() time.Time { return now }, func() uint64 { return 0 })
	got := q.snapshot(func() time.Time { return now }, func() uint64 { return 0 })
	if got.LagSeconds != 0 || got.Status != "ok" {
		t.Fatalf("newly observed occupancy inherited time before the measurement completed: %+v", got)
	}
}

func kernelQueueSnapshot(q *kernelQueue, now time.Time, consumed uint64) queuehealth.Status {
	return q.snapshot(func() time.Time { return now }, func() uint64 { return consumed })
}
func finishKernelQueue(q *kernelQueue, now time.Time, consumed uint64) {
	q.finish(func() time.Time { return now }, consumed)
}
