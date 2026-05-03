package broadcast

import (
	"sync"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

func TestBus_FanOutToTwoSubscribers(t *testing.T) {
	bus := NewBus(8)
	defer bus.Close()

	subA := bus.Subscribe()
	subB := bus.Subscribe()

	finding := alert.Finding{Check: "x", Severity: alert.High}
	bus.Publish(finding)

	var wg sync.WaitGroup
	wg.Add(2)
	gotA, gotB := false, false

	go func() {
		defer wg.Done()
		select {
		case f := <-subA:
			if f.Check == "x" {
				gotA = true
			}
		case <-time.After(time.Second):
		}
	}()
	go func() {
		defer wg.Done()
		select {
		case f := <-subB:
			if f.Check == "x" {
				gotB = true
			}
		case <-time.After(time.Second):
		}
	}()
	wg.Wait()
	if !gotA || !gotB {
		t.Fatalf("expected both subscribers to receive: gotA=%v gotB=%v", gotA, gotB)
	}
}

func TestBus_SlowSubscriberDoesNotBlockOthers(t *testing.T) {
	bus := NewBus(2) // tiny buffer
	defer bus.Close()

	slow := bus.Subscribe()
	fast := bus.Subscribe()

	for i := 0; i < 10; i++ {
		bus.Publish(alert.Finding{Check: "x"})
	}

	// Fast subscriber must drain at least 2 in <100ms (buffered).
	count := 0
	deadline := time.After(100 * time.Millisecond)
loop:
	for {
		select {
		case <-fast:
			count++
		case <-deadline:
			break loop
		}
	}
	if count < 2 {
		t.Fatalf("fast subscriber starved by slow one: drained %d", count)
	}
	_ = slow
}

func TestBus_UnsubscribeStopsDelivery(t *testing.T) {
	bus := NewBus(8)
	defer bus.Close()

	ch := bus.Subscribe()
	bus.Unsubscribe(ch)
	bus.Publish(alert.Finding{Check: "x"})

	select {
	case f, ok := <-ch:
		if ok {
			t.Fatalf("expected channel closed/empty, got %+v", f)
		}
	case <-time.After(50 * time.Millisecond):
		// channel never received - acceptable
	}
}

func TestBus_CloseDrainsAllSubscribers(t *testing.T) {
	bus := NewBus(8)
	chA := bus.Subscribe()
	chB := bus.Subscribe()
	bus.Close()

	if _, ok := <-chA; ok {
		t.Fatal("expected chA closed")
	}
	if _, ok := <-chB; ok {
		t.Fatal("expected chB closed")
	}
}
