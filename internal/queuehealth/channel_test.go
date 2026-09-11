package queuehealth

import (
	"sync"
	"testing"
	"time"
)

func TestChannelTracksAdmissionThroughProcessing(t *testing.T) {
	now := time.Unix(1000, 0)
	q := NewChannel[int](2, time.Minute)
	q.now = func() time.Time { return now }
	if !q.TrySend(10) || !q.TrySend(20) || q.TrySend(30) {
		t.Fatal("channel did not enforce its two waiting slots")
	}
	first, second := <-q.Items(), <-q.Items()
	if first.Value != 10 || second.Value != 20 {
		t.Fatalf("queue changed delivery order: %d, %d", first.Value, second.Value)
	}
	first.Ticket.Start(now.Add(time.Second))
	second.Ticket.Start(now.Add(2 * time.Second))
	second.Ticket.Finish(now.Add(3 * time.Second))
	got := q.Snapshot(now.Add(62 * time.Second))
	if got.Depth != 0 || got.Capacity != 2 || got.InFlight != 1 || got.ProcessingSeconds != 61 || got.Reason != "processing_lag" || got.DroppedTotal != 1 {
		t.Fatalf("received work disappeared before completion: %+v", got)
	}
	first.Ticket.Finish(now.Add(63 * time.Second))
	if got := q.Snapshot(now.Add(64 * time.Second)); got.Status != "ok" || got.InFlight != 0 || got.DroppedTotal != 1 || got.RecentDrops != 0 {
		t.Fatalf("completion lost cumulative evidence or failed to recover: %+v", got)
	}
	q.Close()
}

func TestChannelCountsCanceledAdmissionAndShutdownWork(t *testing.T) {
	now := time.Now()
	q := NewChannel[int](1, time.Minute)
	q.now = func() time.Time { return now }
	if !q.TrySend(10) {
		t.Fatal("empty channel rejected work")
	}
	stop, finished := make(chan struct{}), make(chan bool, 1)
	go func() { finished <- q.Send(20, stop) }()
	deadline := time.After(5 * time.Second)
	for q.Snapshot(now).Depth != 2 {
		select {
		case <-deadline:
			close(stop)
			<-finished
			t.Fatal("blocked producer was not visible")
		default:
			time.Sleep(time.Millisecond)
		}
	}
	close(stop)
	if <-finished {
		t.Fatal("canceled admission claimed success on a full channel")
	}
	if got := q.Snapshot(now); got.Depth != 1 || got.InFlight != 0 || got.DroppedTotal != 1 || got.RecentDrops != 1 {
		t.Fatalf("canceled admission concealed or double-counted work: %+v", got)
	}
	q.Close()
	q.DiscardPending()
	q.DiscardPending()
	if got := q.Snapshot(now); got.Depth != 0 || got.InFlight != 0 || got.DroppedTotal != 2 || got.RecentDrops != 2 {
		t.Fatalf("shutdown did not count the one retained item exactly once: %+v", got)
	}
}

func TestChannelFastConsumersCannotOutrunAccounting(t *testing.T) {
	q := NewChannel[int](4, time.Minute)
	counts := make([]int, 800)
	var mu sync.Mutex
	var consumers sync.WaitGroup
	for i := 0; i < 4; i++ {
		consumers.Go(func() {
			for work := range q.Items() {
				work.Ticket.Start(time.Now())
				mu.Lock()
				counts[work.Value]++
				mu.Unlock()
				work.Ticket.Finish(time.Now())
			}
		})
	}
	var producers sync.WaitGroup
	for i := 0; i < 8; i++ {
		producers.Go(func() {
			for j := 0; j < 100; j++ {
				if !q.Send(i*100+j, nil) {
					t.Error("uncanceled producer lost an item")
				}
				q.Snapshot(time.Now())
			}
		})
	}
	producers.Wait()
	q.Close()
	consumers.Wait()
	for value, count := range counts {
		if count != 1 {
			t.Fatalf("value %d delivered %d times, want once", value, count)
		}
	}
	if got := q.Snapshot(time.Now()); got.Depth != 0 || got.InFlight != 0 || got.DroppedTotal != 0 {
		t.Fatalf("fast completion raced admission accounting: %+v", got)
	}
}

func TestChannelProcessingTracksPanicsAndNormalReturns(t *testing.T) {
	q := NewChannel[int](1, time.Minute)
	for _, fail := range []bool{false, true} {
		if !q.TrySend(42) {
			t.Fatal("empty queue refused work")
		}
		work := <-q.Items()
		panicked := false
		func() {
			defer func() { panicked = recover() != nil }()
			work.Process(func(value int) {
				if value != 42 {
					t.Errorf("processor received %d, want 42", value)
				}
				got := q.Snapshot(time.Now().Add(61 * time.Second))
				if got.Depth != 0 || got.InFlight != 1 || got.Reason != "processing_lag" {
					t.Errorf("active processing was not tracked: %+v", got)
				}
				if fail {
					panic("worker failure")
				}
			})
		}()
		if panicked != fail {
			t.Fatalf("processing hid a panic or failed unexpectedly: fail=%v panicked=%v", fail, panicked)
		}
	}
	q.Lose(2)
	if got := q.Snapshot(time.Now()); got.Depth != 0 || got.InFlight != 0 || got.DroppedTotal != 3 || got.RecentDrops != 3 || got.Reason != "dropped_work" {
		t.Fatalf("panic or upstream losses were not counted exactly: %+v", got)
	}
	q.Close()
}
