package checks

import (
	"context"
	"runtime"
	"testing"
	"time"
)

func TestScanBatchQueueBudgetsAndIndependentPeers(t *testing.T) {
	m := newScanBatchMonitor()
	a := m.begin(3, 2)
	b := m.begin(1, 1)
	a.tasks[0].admit()
	a.tasks[1].admit()
	b.tasks[0].admit()
	a.tasks[0].executing(context.Background(), 10*time.Minute)
	a.tasks[1].executing(context.Background(), 10*time.Minute)
	b.tasks[0].executing(context.Background(), 30*time.Second)
	q := m.snapshot(time.Now().Add(61 * time.Second))
	if q.Depth != 1 || q.InFlight != 3 || q.Reason != "processing_lag" || !q.CapacityUnavailable || q.DroppedTotal != 0 {
		t.Fatalf("long jobs masked an overdue peer: %+v", q)
	}
	b.tasks[0].finish()
	if q := m.snapshot(time.Now().Add(61 * time.Second)); q.Status != "ok" || q.Depth != 1 || q.InFlight != 2 {
		t.Fatalf("normal busy pool was reported as stalled: %+v", q)
	}
	a.tasks[0].finish()
	if q := m.snapshot(time.Now().Add(61 * time.Second)); q.Reason != "backlog_lag" || q.Depth != 1 || q.InFlight != 1 {
		t.Fatalf("free slot without dispatch progress was hidden: %+v", q)
	}
	a.tasks[1].progress()
	if q := m.snapshot(time.Now().Add(61 * time.Second)); q.Reason != "processing_lag" {
		t.Fatalf("cleanup borrowed the execution budget: %+v", q)
	}
	a.tasks[1].finish()
	a.abandon(context.Background())
	if q := m.snapshot(time.Now().Add(time.Minute)); q.Status != "ok" || q.Depth != 0 || q.InFlight != 0 || q.DroppedTotal != 1 {
		t.Fatalf("abandoned waiting job and recovery: %+v", q)
	}
}

func TestScanBatchQueueFailureAndAbnormalExit(t *testing.T) {
	m := newScanBatchMonitor()
	b := m.begin(3, 3)
	for _, task := range b.tasks {
		task.admit()
	}
	b.tasks[0].run(context.Background(), time.Minute, func() {
		b.tasks[0].fail()
		b.tasks[0].fail()
		if q := m.snapshot(time.Now()); q.DroppedTotal != 1 || q.InFlight != 3 {
			t.Fatalf("known failure was delayed or counted twice: %+v", q)
		}
	})
	func() {
		defer func() {
			if recover() != "fixture panic" {
				t.Error("panic policy changed")
			}
		}()
		b.tasks[1].run(context.Background(), time.Minute, func() { panic("fixture panic") })
	}()
	done := make(chan struct{})
	go func() {
		defer close(done)
		b.tasks[2].run(context.Background(), time.Minute, runtime.Goexit)
	}()
	<-done
	q := m.snapshot(time.Now())
	if q.Depth != 0 || q.InFlight != 0 || q.DroppedTotal != 3 || q.Reason != "dropped_work" {
		t.Fatalf("failed task drain: %+v", q)
	}
	if q := m.snapshot(time.Now().Add(time.Minute)); q.Status != "ok" || q.DroppedTotal != 3 || q.RecentDrops != 0 {
		t.Fatalf("failed batch recovery: %+v", q)
	}
}

func TestScanBatchQueueWaitingCancellationAndDeadline(t *testing.T) {
	for _, deadline := range []bool{false, true} {
		m := newScanBatchMonitor()
		b := m.begin(3, 2)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		var want uint64
		if deadline {
			var stop context.CancelFunc
			ctx, stop = context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
			defer stop()
			want = 3
		}
		b.abandon(ctx)
		b.abandon(ctx)
		q := m.snapshot(time.Now())
		if q.Depth != 0 || q.InFlight != 0 || q.DroppedTotal != want {
			t.Fatalf("waiting withdrawal deadline=%v: %+v want=%d", deadline, q, want)
		}
	}
}
