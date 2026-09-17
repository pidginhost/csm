package broadcast

import (
	"errors"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/queuehealth"
)

func TestBusPublishesQueuePressure(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		bus := NewBus(2)
		defer bus.Close()
		sub := bus.Subscribe()
		defer bus.Unsubscribe(sub)
		for range 5 {
			bus.Publish(alert.Finding{Check: "test"})
		}
		provider, ok := any(bus).(interface {
			QueueStatuses(time.Time) map[string]queuehealth.Status
		})
		if !ok {
			t.Fatal("finding bus hides overflow from queue health")
		}
		rows := provider.QueueStatuses(time.Now())
		q := rows["deliveries"]
		if len(rows) != 1 || q.Capacity != 2 || q.Depth != 2 || q.InFlight != 0 || q.DroppedTotal != 3 || q.RecentDrops != 3 || q.Reason != "dropped_work" {
			t.Fatalf("queue evidence = %+v", rows)
		}
		time.Sleep(30 * time.Second)
		q = provider.QueueStatuses(time.Now())["deliveries"]
		if q.LagSeconds != 30 || q.Reason != "queue_full" {
			t.Fatalf("sustained saturation = %+v", q)
		}
	})
}

func TestBusOneFullSubscriberDegradesAggregate(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		bus := NewBus(2)
		defer bus.Close()
		slow, fast := bus.Subscribe(), bus.Subscribe()
		defer bus.Unsubscribe(slow)
		defer bus.Unsubscribe(fast)
		for range 2 {
			bus.Publish(alert.Finding{})
			receiveFinding(t, fast)
		}
		time.Sleep(30 * time.Second)
		q := bus.QueueStatuses(time.Now())["deliveries"]
		if q.Capacity != 4 || q.Depth != 2 || q.InFlight != 0 || q.DroppedTotal != 0 || q.Reason != "queue_full" {
			t.Fatalf("isolated slow subscriber = %+v", q)
		}
		receiveFinding(t, slow)
		q = bus.QueueStatuses(time.Now())["deliveries"]
		if q.Status != "ok" || q.Depth != 1 || q.LagSeconds != 30 {
			t.Fatalf("freed slot = %+v", q)
		}
		time.Sleep(30 * time.Second)
		q = bus.QueueStatuses(time.Now())["deliveries"]
		if q.Reason != "backlog_lag" || q.LagSeconds != 60 {
			t.Fatalf("old delivery = %+v", q)
		}
	})
}

func TestBusUnsubscribePreservesOwnedDelivery(t *testing.T) {
	for _, failed := range []bool{false, true} {
		name := "cancel"
		if failed {
			name = "abort"
		}
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				bus := NewBus(3)
				defer bus.Close()
				sub := bus.Subscribe()
				for range 3 {
					bus.Publish(alert.Finding{})
				}
				delivery := <-sub.Events()
				release := make(chan struct{})
				finished := make(chan error, 1)
				wantErr := errors.New("write failed")
				go func() { finished <- delivery.Process(func(alert.Finding) error { <-release; return wantErr }) }()
				synctest.Wait()
				if failed {
					bus.Abort(sub)
				} else {
					bus.Unsubscribe(sub)
				}
				time.Sleep(time.Minute)
				q := bus.QueueStatuses(time.Now())["deliveries"]
				var wantDrops uint64
				if failed {
					wantDrops = 2
				}
				if q.Capacity != 0 || q.Depth != 0 || q.InFlight != 1 || q.DroppedTotal != wantDrops || q.ProcessingSeconds != 60 || q.Reason != "processing_lag" {
					t.Fatalf("owned after removal = %+v", q)
				}
				close(release)
				if err := <-finished; err != wantErr {
					t.Fatalf("process error = %v", err)
				}
				q = bus.QueueStatuses(time.Now())["deliveries"]
				if q.Depth != 0 || q.InFlight != 0 || q.DroppedTotal != wantDrops+1 || q.RecentDrops != 1 {
					t.Fatalf("settled delivery = %+v", q)
				}
				requireClosed(t, sub)
			})
		})
	}
}

func TestBusDeliveryPanicCountsOnce(t *testing.T) {
	bus := NewBus(2)
	defer bus.Close()
	sub := bus.Subscribe()
	for range 2 {
		bus.Publish(alert.Finding{})
	}
	func() {
		defer func() {
			if got := recover(); got != "delivery panic" {
				t.Fatalf("panic = %v", got)
			}
		}()
		delivery := <-sub.Events()
		_ = delivery.Process(func(alert.Finding) error { panic("delivery panic") })
	}()
	bus.Abort(sub)
	bus.Abort(sub)
	q := bus.QueueStatuses(time.Now())["deliveries"]
	if q.Capacity != 0 || q.Depth != 0 || q.InFlight != 0 || q.DroppedTotal != 2 {
		t.Fatalf("panic settlement = %+v", q)
	}
}

func TestBusChurnRetainsLossWithoutRetiredSubscribers(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		bus := NewBus(2)
		defer bus.Close()
		for range 300 {
			sub := bus.Subscribe()
			for range 5 {
				bus.Publish(alert.Finding{})
			}
			bus.Unsubscribe(sub)
		}
		q := bus.QueueStatuses(time.Now())["deliveries"]
		if len(bus.subscribers) != 0 || q.Capacity != 0 || q.Depth != 0 || q.InFlight != 0 || q.DroppedTotal != 900 || q.RecentDrops != 900 || q.Reason != "dropped_work" {
			t.Fatalf("subscriber churn = %+v", q)
		}
		time.Sleep(time.Minute)
		q = bus.QueueStatuses(time.Now())["deliveries"]
		if q.Status != "ok" || q.DroppedTotal != 900 || q.RecentDrops != 0 {
			t.Fatalf("loss recovery = %+v", q)
		}
	})
}

func TestBusConcurrentCloseAbortAndOwnedDelivery(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		bus := NewBus(128)
		sub := bus.Subscribe()
		var publishers sync.WaitGroup
		for range 128 {
			publishers.Go(func() { bus.Publish(alert.Finding{}) })
		}
		publishers.Wait()
		delivery := <-sub.Events()
		release := make(chan struct{})
		done := make(chan error, 1)
		go func() { done <- delivery.Process(func(alert.Finding) error { <-release; return nil }) }()
		synctest.Wait()
		var closers sync.WaitGroup
		closers.Go(bus.Close)
		closers.Go(func() { bus.Abort(sub) })
		closers.Wait()
		bus.Publish(alert.Finding{})
		q := bus.QueueStatuses(time.Now())["deliveries"]
		if q.Depth != 0 || q.InFlight != 1 || q.Capacity != 0 || q.DroppedTotal != 127 {
			t.Fatalf("concurrent closure = %+v", q)
		}
		close(release)
		if err := <-done; err != nil {
			t.Fatal(err)
		}
		q = bus.QueueStatuses(time.Now())["deliveries"]
		if q.InFlight != 0 || q.Depth != 0 || q.DroppedTotal != 127 {
			t.Fatalf("final ownership = %+v", q)
		}
	})
}

func TestBusDeliveriesAreAdvisory(t *testing.T) {
	bus := NewBus(1)
	defer bus.Close()
	if q := bus.QueueStatuses(time.Now())["deliveries"]; !q.Advisory {
		t.Fatalf("a client that stops reading can degrade the host: %+v", q)
	}
}
