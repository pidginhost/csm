package queuehealth

import (
	"sync"
	"testing"
	"time"
)

func TestTrackerMeasuresWaitingAndRunningWork(t *testing.T) {
	now := time.Unix(1000, 0)
	q := New(4, time.Minute)
	first := q.Begin(now)
	second := q.Begin(now.Add(10 * time.Second))
	first.Start(now.Add(20 * time.Second))
	s := q.Snapshot(now.Add(30 * time.Second))
	if s.Depth != 1 || s.InFlight != 1 || s.Capacity != 4 || s.LagSeconds != 20 || s.ProcessingSeconds != 10 || s.Status != "ok" {
		t.Fatalf("waiting and active work were conflated: %+v", s)
	}
	second.Start(now.Add(31 * time.Second))
	second.Finish(now.Add(32 * time.Second))
	s = q.Snapshot(now.Add(81 * time.Second))
	if s.Depth != 0 || s.InFlight != 1 || s.Status != "degraded" || s.Reason != "processing_lag" || s.ProcessingSeconds != 61 {
		t.Fatalf("out-of-order completion hid stalled worker: %+v", s)
	}
	first.Finish(now.Add(82 * time.Second))
	s = q.Snapshot(now.Add(83 * time.Second))
	if s.Depth != 0 || s.InFlight != 0 || s.LagSeconds != 0 || s.ProcessingSeconds != 0 || s.Status != "ok" {
		t.Fatalf("drained queue did not recover: %+v", s)
	}
}

func TestTrackerBacklogAgesWhileConsumersMakeProgress(t *testing.T) {
	now := time.Unix(1000, 0)
	q := New(4, time.Minute)
	first := q.Begin(now)
	second := q.Begin(now.Add(time.Second))
	first.Start(now.Add(59 * time.Second))
	first.Finish(now.Add(60 * time.Second))
	s := q.Snapshot(now.Add(62 * time.Second))
	if s.LagSeconds != 61 || s.Status != "degraded" || s.Reason != "backlog_lag" {
		t.Fatalf("one completed item hid an old queued item: %+v", s)
	}
	second.Start(now.Add(63 * time.Second))
	second.Finish(now.Add(64 * time.Second))
	if s := q.Snapshot(now.Add(65 * time.Second)); s.Status != "ok" {
		t.Fatalf("queue stayed degraded after draining: %+v", s)
	}
}

func TestTrackerSustainedFullQueueAndRecovery(t *testing.T) {
	now := time.Unix(1000, 0)
	q := New(1, time.Minute)
	work := q.Begin(now)
	if s := q.Snapshot(now.Add(29 * time.Second)); s.Status != "ok" {
		t.Fatalf("brief full queue degraded: %+v", s)
	}
	if s := q.Snapshot(now.Add(30 * time.Second)); s.Status != "degraded" || s.Reason != "queue_full" {
		t.Fatalf("sustained full queue stayed healthy: %+v", s)
	}
	work.Start(now.Add(31 * time.Second))
	work.Finish(now.Add(32 * time.Second))
	next := q.Begin(now.Add(33 * time.Second))
	if s := q.Snapshot(now.Add(34 * time.Second)); s.Status != "ok" {
		t.Fatalf("full timer survived queue recovery: %+v", s)
	}
	next.Finish(now.Add(35 * time.Second))
}

func TestTrackerDropsRemainVisibleAfterQueueDrains(t *testing.T) {
	now := time.Unix(1000, 0)
	q := New(1, time.Minute)
	for i := 0; i < 3; i++ {
		x := q.Begin(now.Add(time.Duration(i) * time.Second))
		x.Reject(now.Add(time.Duration(i) * time.Second))
	}
	s := q.Snapshot(now.Add(3 * time.Second))
	if s.Depth != 0 || s.InFlight != 0 || s.DroppedTotal != 3 || s.RecentDrops != 3 || s.Status != "degraded" || s.Reason != "dropped_work" {
		t.Fatalf("rejected work disappeared from health: %+v", s)
	}
	s = q.Snapshot(now.Add(62 * time.Second))
	if s.Status != "ok" || s.RecentDrops != 0 || s.DroppedTotal != 3 {
		t.Fatalf("recovery lost cumulative evidence or failed to expire the window: %+v", s)
	}
	q.Lose(now.Add(63*time.Second), 5)
	s = q.Snapshot(now.Add(64 * time.Second))
	if s.DroppedTotal != 8 || s.RecentDrops != 5 || s.Status != "degraded" {
		t.Fatalf("kernel loss not counted without a userspace ticket: %+v", s)
	}
}

func TestTrackerOneDropDoesNotManufactureSustainedOverload(t *testing.T) {
	now := time.Unix(1000, 0)
	q := New(1, time.Minute)
	q.Lose(now, 1)
	s := q.Snapshot(now.Add(time.Second))
	if s.Status != "ok" || s.DroppedTotal != 1 || s.RecentDrops != 1 {
		t.Fatalf("isolated loss must stay visible without an overload alarm: %+v", s)
	}
}

func TestTrackerConcurrentProducersConsumersAndSnapshots(t *testing.T) {
	q := New(32, time.Minute)
	var wg sync.WaitGroup
	for worker := 0; worker < 16; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				now := time.Now()
				work := q.Begin(now)
				if i%2 == 0 {
					work.Reject(now)
				} else {
					work.Start(now)
					work.Finish(now)
				}
				_ = q.Snapshot(now)
			}
		}()
	}
	wg.Wait()
	s := q.Snapshot(time.Now())
	if s.Depth != 0 || s.InFlight != 0 || s.DroppedTotal != 800 {
		t.Fatalf("concurrent accounting lost work: %+v", s)
	}
}

func TestTrackerRetryPreservesOriginalWaitingAge(t *testing.T) {
	now := time.Unix(1000, 0)
	q := New(2, time.Minute)
	item := q.Begin(now)
	item.Start(now.Add(10 * time.Second))
	item.Requeue(now.Add(20 * time.Second))
	if got := q.Snapshot(now.Add(30 * time.Second)); got.Depth != 1 || got.InFlight != 0 || got.LagSeconds != 30 || got.ProcessingSeconds != 0 || got.DroppedTotal != 0 {
		t.Fatalf("retry changed admission age or lost accounting: %+v", got)
	}
	item.Start(now.Add(35 * time.Second))
	item.Requeue(now.Add(45 * time.Second))
	if got := q.Snapshot(now.Add(60 * time.Second)); got.Status != "degraded" || got.Reason != "backlog_lag" || got.LagSeconds != 60 {
		t.Fatalf("retries hid a stalled work item: %+v", got)
	}
	item.Start(now.Add(61 * time.Second))
	item.Finish(now.Add(62 * time.Second))
	if got := q.Snapshot(now.Add(63 * time.Second)); got.Status != "ok" || got.Depth != 0 || got.InFlight != 0 || got.DroppedTotal != 0 {
		t.Fatalf("completed retry did not recover: %+v", got)
	}
	var synchronous Ticket
	synchronous.Requeue(now)
}

func TestTrackerSharedCapacityIncludesRunningReservations(t *testing.T) {
	now := time.Unix(1000, 0)
	q := NewSharedCapacity(2, time.Minute)
	first, second := q.Begin(now), q.Begin(now)
	first.Start(now.Add(time.Second))
	second.Start(now.Add(2 * time.Second))
	if got := q.Snapshot(now.Add(30 * time.Second)); got.Status != "degraded" || got.Reason != "queue_full" || got.Depth != 0 || got.InFlight != 2 {
		t.Fatalf("running work released reserved capacity: %+v", got)
	}
	first.Finish(now.Add(31 * time.Second))
	if got := q.Snapshot(now.Add(32 * time.Second)); got.Status != "ok" || got.InFlight != 1 {
		t.Fatalf("finished item did not release its reservation: %+v", got)
	}
	third := q.Begin(now.Add(33 * time.Second))
	if got := q.Snapshot(now.Add(34 * time.Second)); got.Status != "ok" || got.Depth != 1 || got.InFlight != 1 {
		t.Fatalf("old full timer survived a released slot: %+v", got)
	}
	second.Finish(now.Add(35 * time.Second))
	third.Finish(now.Add(35 * time.Second))
}

func TestTrackerAdmissionAgeDoesNotBackdateSaturation(t *testing.T) {
	now := time.Unix(1000, 0)
	q := NewSharedCapacity(1, 2*time.Minute)
	item := q.BeginAt(now.Add(-45*time.Second), now)
	if got := q.Snapshot(now); got.Status != "ok" || got.Depth != 1 || got.LagSeconds != 45 {
		t.Fatalf("existing work age backdated a new admission: %+v", got)
	}
	if got := q.Snapshot(now.Add(30 * time.Second)); got.Status != "degraded" || got.Reason != "queue_full" || got.LagSeconds != 75 {
		t.Fatalf("actual saturation start did not drive the full timer: %+v", got)
	}
	item.Finish(now.Add(31 * time.Second))
}
