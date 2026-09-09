package alert

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/queuehealth"
)

func TestRegisteredQueueAccountsForLossAndCompletion(t *testing.T) {
	ch := make(chan Finding, 1)
	q := queuehealth.New(cap(ch), time.Minute)
	unregister := RegisterQueue(ch, q)
	defer unregister()
	want := Finding{Check: "test_alert", Message: "test finding", Timestamp: time.Now()}
	if !TryEnqueue(ch, want) {
		t.Fatal("empty queue refused finding")
	}
	for i := 0; i < 3; i++ {
		if TryEnqueue(ch, want) {
			t.Fatal("full queue accepted finding")
		}
	}
	if s := q.Snapshot(time.Now()); s.Depth != 1 || s.DroppedTotal != 3 || s.Status != "degraded" {
		t.Fatalf("queue loss was not retained: %+v", s)
	}
	got := <-ch
	StartQueued(got)
	if s := q.Snapshot(time.Now()); s.Depth != 0 || s.InFlight != 1 {
		t.Fatalf("received finding is not tracked until dispatch completes: %+v", s)
	}
	raw, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "queue") || got.Check != want.Check || got.Message != want.Message || !got.Timestamp.Equal(want.Timestamp) {
		t.Fatalf("queue metadata changed the public finding: %s", raw)
	}
	FinishQueued([]Finding{got})
	if s := q.Snapshot(time.Now()); s.Depth != 0 || s.InFlight != 0 || s.DroppedTotal != 3 {
		t.Fatalf("completed finding retained work: %+v", s)
	}
}

func TestTimedEnqueueCountsOnlyActualLoss(t *testing.T) {
	ch := make(chan Finding, 1)
	q := queuehealth.New(1, time.Minute)
	defer RegisterQueue(ch, q)()
	if err := EnqueueWithin(ch, Finding{Check: "test_alert"}, nil, time.Second); err != nil {
		t.Fatal(err)
	}
	if err := EnqueueWithin(ch, Finding{Check: "test_alert"}, nil, time.Millisecond); !errors.Is(err, ErrQueueTimeout) {
		t.Fatalf("full queue error = %v, want timeout", err)
	}
	if s := q.Snapshot(time.Now()); s.Depth != 1 || s.DroppedTotal != 1 {
		t.Fatalf("initial backpressure and timeout counted twice: %+v", s)
	}
	first := <-ch
	StartQueued(first)
	FinishQueued([]Finding{first})
	stop := make(chan struct{})
	close(stop)
	unbuffered := make(chan Finding)
	q2 := queuehealth.New(0, time.Minute)
	defer RegisterQueue(unbuffered, q2)()
	if err := EnqueueWithin(unbuffered, Finding{Check: "test_alert"}, stop, time.Hour); !errors.Is(err, ErrQueueStopped) {
		t.Fatalf("stopped queue error = %v, want shutdown", err)
	}
	RecordQueueLoss(ch, 4)
	if s := q.Snapshot(time.Now()); s.Depth != 0 || s.DroppedTotal != 5 {
		t.Fatalf("abandoned batch not included in delivery loss: %+v", s)
	}
}

func TestQueueRegistrationIsScopedToChannelLifetime(t *testing.T) {
	ch := make(chan Finding, 1)
	q := queuehealth.New(1, time.Minute)
	unregister := RegisterQueue(ch, q)
	unregister()
	if !TryEnqueue(ch, Finding{Check: "test_alert"}) {
		t.Fatal("standalone channel stopped receiving")
	}
	got := <-ch
	StartQueued(got)
	FinishQueued([]Finding{got})
	if s := q.Snapshot(time.Now()); s.Depth != 0 || s.InFlight != 0 || s.DroppedTotal != 0 {
		t.Fatalf("unregistered queue still accounted work: %+v", s)
	}
}

func TestBlockingEnqueueStopsWithoutLeakingPendingWork(t *testing.T) {
	ch := make(chan Finding)
	q := queuehealth.New(0, time.Minute)
	defer RegisterQueue(ch, q)()
	stop := make(chan struct{})
	close(stop)
	if Enqueue(ch, Finding{Check: "test_alert"}, stop) {
		t.Fatal("send to undrained queue succeeded during shutdown")
	}
	if s := q.Snapshot(time.Now()); s.Depth != 0 || s.InFlight != 0 || s.DroppedTotal != 1 {
		t.Fatalf("cancelled send leaked pending work or lost evidence: %+v", s)
	}
}

func TestForwardedFindingDoesNotRetainCompletedQueueTicket(t *testing.T) {
	first := make(chan Finding, 1)
	q := queuehealth.New(1, time.Minute)
	defer RegisterQueue(first, q)()
	if !TryEnqueue(first, Finding{Check: "test_alert"}) {
		t.Fatal("first queue refused finding")
	}
	f := <-first
	StartQueued(f)
	FinishQueued([]Finding{f})
	observer := make(chan Finding, 1)
	if !TryEnqueue(observer, f) {
		t.Fatal("observer queue refused finding")
	}
	f = <-observer
	StartQueued(f)
	FinishQueued([]Finding{f})
	if s := q.Snapshot(time.Now()); s.Depth != 0 || s.InFlight != 0 || s.DroppedTotal != 0 {
		t.Fatalf("forwarding an observed finding reused its completed ticket: %+v", s)
	}
}
