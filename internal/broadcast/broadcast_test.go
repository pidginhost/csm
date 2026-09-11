package broadcast

import (
	"fmt"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
)

func receiveFinding(t *testing.T, sub *Subscription) alert.Finding {
	t.Helper()
	select {
	case delivery, ok := <-sub.Events():
		if !ok {
			t.Fatal("subscription closed before delivery")
		}
		var finding alert.Finding
		if err := delivery.Process(func(f alert.Finding) error { finding = f; return nil }); err != nil {
			t.Fatal(err)
		}
		return finding
	default:
		t.Fatal("expected buffered delivery")
		return alert.Finding{}
	}
}

func requireClosed(t *testing.T, sub *Subscription) {
	t.Helper()
	select {
	case _, ok := <-sub.Events():
		if ok {
			t.Fatal("expected closed and empty subscription")
		}
	default:
		t.Fatal("subscription is not closed")
	}
}

func TestBus_FanOutToTwoSubscribers(t *testing.T) {
	bus := NewBus(8)
	defer bus.Close()
	a, b := bus.Subscribe(), bus.Subscribe()
	defer bus.Unsubscribe(a)
	defer bus.Unsubscribe(b)
	for i := range 3 {
		bus.Publish(alert.Finding{Check: fmt.Sprint(i), Severity: alert.High})
	}
	for _, sub := range []*Subscription{a, b} {
		for i := range 3 {
			f := receiveFinding(t, sub)
			if f.Check != fmt.Sprint(i) || f.Severity != alert.High {
				t.Fatalf("delivery %d = %+v", i, f)
			}
		}
	}
}

func TestBus_SlowSubscriberDoesNotBlockOthers(t *testing.T) {
	bus := NewBus(2)
	defer bus.Close()
	slow, fast := bus.Subscribe(), bus.Subscribe()
	defer bus.Unsubscribe(slow)
	defer bus.Unsubscribe(fast)
	for i := range 10 {
		bus.Publish(alert.Finding{Check: fmt.Sprint(i)})
		if f := receiveFinding(t, fast); f.Check != fmt.Sprint(i) {
			t.Fatalf("fast delivery %d = %+v", i, f)
		}
	}
	for i := range 2 {
		if f := receiveFinding(t, slow); f.Check != fmt.Sprint(i) {
			t.Fatalf("slow delivery %d = %+v", i, f)
		}
	}
	select {
	case <-slow.Events():
		t.Fatal("slow subscriber retained more than its capacity")
	default:
	}
}

func TestBus_UnsubscribeStopsDelivery(t *testing.T) {
	bus := NewBus(8)
	defer bus.Close()
	sub := bus.Subscribe()
	bus.Publish(alert.Finding{Check: "withdrawn"})
	bus.Unsubscribe(sub)
	bus.Unsubscribe(sub)
	bus.Publish(alert.Finding{Check: "late"})
	requireClosed(t, sub)
}

func TestBus_CloseDrainsAllSubscribers(t *testing.T) {
	bus := NewBus(8)
	a, b := bus.Subscribe(), bus.Subscribe()
	bus.Publish(alert.Finding{Check: "retained"})
	bus.Close()
	bus.Close()
	bus.Publish(alert.Finding{Check: "late"})
	for _, sub := range []*Subscription{a, b} {
		if f := receiveFinding(t, sub); f.Check != "retained" {
			t.Fatalf("buffered delivery = %+v", f)
		}
		requireClosed(t, sub)
		bus.Unsubscribe(sub)
	}
}

func TestBus_SubscribeAfterCloseReturnsClosedChannel(t *testing.T) {
	bus := NewBus(8)
	bus.Close()
	requireClosed(t, bus.Subscribe())
	sub, ok := bus.TrySubscribe()
	if !ok {
		t.Fatal("closed bus refused an empty closed subscription")
	}
	requireClosed(t, sub)
}

func TestBus_TrySubscribeEnforcesCap(t *testing.T) {
	bus := NewBus(4)
	defer bus.Close()
	bus.SetMaxSubscribers(2)
	a, ok := bus.TrySubscribe()
	if !ok {
		t.Fatal("first subscription refused")
	}
	b, ok := bus.TrySubscribe()
	if !ok {
		t.Fatal("second subscription refused")
	}
	defer bus.Unsubscribe(b)
	if extra, admitted := bus.TrySubscribe(); admitted || extra != nil {
		t.Fatal("subscription beyond cap accepted")
	}
	bus.Unsubscribe(a)
	c, ok := bus.TrySubscribe()
	if !ok {
		t.Fatal("freed slot refused")
	}
	bus.Unsubscribe(c)
}
