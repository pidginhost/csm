package queuehealth

import (
	"sync"
	"testing"
	"time"
)

func TestSampledQueueDistinguishesProgressFromWaitingAge(t *testing.T) {
	now := time.Unix(1000, 0)
	q := NewSampled(4096, "bytes", time.Minute)
	q.Observe(now, 512, 10)
	q.Observe(now.Add(30*time.Second), 1024, 10)
	got := q.Snapshot(now.Add(61 * time.Second))
	if got.Depth != 1024 || got.Capacity != 4096 || got.DepthUnit != "bytes" || got.LagBasis != "consumer_progress" || got.LagSeconds != 61 || got.Reason != "consumer_stalled" {
		t.Fatalf("unconsumed kernel work was hidden or given invented item age: %+v", got)
	}
	q.Observe(now.Add(62*time.Second), 512, 11)
	if got := q.Snapshot(now.Add(63 * time.Second)); got.Status != "ok" || got.LagSeconds != 1 || got.Depth != 512 {
		t.Fatalf("consumer progress did not reset the observed stall: %+v", got)
	}
	q.Observe(now.Add(64*time.Second), 0, 12)
	if got := q.Snapshot(now.Add(time.Hour)); got.Status != "ok" || got.LagSeconds != 0 || got.Depth != 0 {
		t.Fatalf("drained kernel queue retained an invented backlog: %+v", got)
	}
}

func TestSampledQueueReportsPressureAndRetainsLoss(t *testing.T) {
	now := time.Unix(1000, 0)
	q := NewSampled(8, "items", time.Minute)
	q.Observe(now, 8, 0)
	if got := q.Snapshot(now.Add(29 * time.Second)); got.Status != "ok" {
		t.Fatalf("short full period degraded prematurely: %+v", got)
	}
	if got := q.Snapshot(now.Add(30 * time.Second)); got.Reason != "queue_full" || got.Depth != 8 {
		t.Fatalf("sustained full queue was not reported: %+v", got)
	}
	q.Lose(now.Add(31*time.Second), 3)
	q.Observe(now.Add(32*time.Second), 0, 8)
	if got := q.Snapshot(now.Add(32 * time.Second)); got.Reason != "dropped_work" || got.DroppedTotal != 3 || got.RecentDrops != 3 || got.LagSeconds != 0 {
		t.Fatalf("drain concealed recent loss: %+v", got)
	}
	if got := q.Snapshot(now.Add(92 * time.Second)); got.Status != "ok" || got.DroppedTotal != 3 || got.RecentDrops != 0 {
		t.Fatalf("recovery lost historical evidence: %+v", got)
	}
}

func TestSampledQueueCanBeObservedWhileStatusIsRead(t *testing.T) {
	q := NewSampled(16, "items", time.Minute)
	var readers sync.WaitGroup
	for range 4 {
		readers.Go(func() {
			for range 1000 {
				got := q.Snapshot(time.Now())
				if got.Depth < 0 || got.Depth > 16 || got.Capacity != 16 || got.InFlight != 0 || got.DepthUnit != "items" || got.LagBasis != "consumer_progress" {
					t.Errorf("invalid concurrent measurement: %+v", got)
					return
				}
			}
		})
	}
	for i := range 1000 {
		q.Observe(time.Now(), i%17, uint64(i))
		q.Lose(time.Now(), 1)
	}
	readers.Wait()
	q.Observe(time.Now(), 0, 1000)
	if got := q.Snapshot(time.Now()); got.Depth != 0 || got.DroppedTotal != 1000 {
		t.Fatalf("concurrent sampling lost measurements: %+v", got)
	}
}
