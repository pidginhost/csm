package blockdigest

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/queuehealth"
)

func digestQueueStatuses(t *testing.T, c *Collector, now time.Time) map[string]queuehealth.Status {
	t.Helper()
	source, ok := any(c).(interface {
		QueueStatuses(time.Time) map[string]queuehealth.Status
	})
	if !ok {
		t.Fatal("collector does not publish actual queue ownership")
	}
	rows := source.QueueStatuses(now)
	row, ok := rows["records"]
	if !ok || row.Capacity != maxBuffered || row.CapacityUnavailable || row.DepthUnit != "records" {
		t.Fatalf("buffer differs from actual bound: found=%v row=%+v", ok, row)
	}
	return rows
}

func TestBlockDigestQueueOverflowAndExpectedCadence(t *testing.T) {
	c := New(Options{Interval: time.Hour, SendOn: "any", MinBlock: 1})
	for range maxBuffered + 3 {
		c.Observe("198.51.100.23", "fixture customer block", time.Unix(0, 0))
	}
	row := digestQueueStatuses(t, c, time.Now())["records"]
	if row.Depth != maxBuffered || row.InFlight != 0 || row.DroppedTotal != 3 || row.RecentDrops != 3 || row.Status != "degraded" {
		t.Fatalf("actual drop-oldest overflow hidden: %+v", row)
	}
	row = digestQueueStatuses(t, c, time.Now().Add(30*time.Minute))["records"]
	if row.Status != "ok" || row.Depth != maxBuffered {
		t.Fatalf("normal interval or old event timestamps reported stalled: %+v", row)
	}
	row = digestQueueStatuses(t, c, time.Now().Add(62*time.Minute))["records"]
	if row.Reason != "backlog_lag" {
		t.Fatalf("overdue digest hidden: %+v", row)
	}
	digest := c.Drain()
	if digest.Total != 1 || len(digest.Records) != 1 || digest.Records[0].IP != "198.51.100.23" {
		t.Fatal("queue observation changed normal per-IP coalescence")
	}
	row = digestQueueStatuses(t, c, time.Now().Add(2*time.Minute))["records"]
	if row.Depth != 0 || row.InFlight != 0 || row.DroppedTotal != 3 || row.Status != "ok" {
		t.Fatalf("expected duplicate coalescence became loss: %+v", row)
	}
}

func TestBlockDigestQueueFailedSinkRemainsOwnedThroughLogging(t *testing.T) {
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	sent := 0
	c := New(Options{Interval: time.Hour, SendOn: "any", MinBlock: 1,
		EmailSink:   func(string, string) error { return errors.New("fixture email failed") },
		WebhookSink: func(p WebhookPayload) error { sent++; return nil },
		OnError: func(channel string, err error) {
			if channel != "email" || err == nil {
				t.Error("sink error callback changed")
			}
			close(entered)
			<-release
		},
	})
	c.Observe("198.51.100.23", "fixture customer block", time.Now())
	t.Cleanup(func() {
		unblock()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("digest flush did not join")
		}
	})
	go func() { defer close(done); c.Flush() }()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("error logger not entered")
	}
	rows := digestQueueStatuses(t, c, time.Now().Add(2*time.Minute))
	email, webhook := rows["email"], rows["webhook"]
	if email.InFlight != 1 || email.DroppedTotal != 1 || email.DroppedLowerBound || email.Reason != "processing_lag" {
		t.Fatalf("failed sink lost ownership before logger returned: %+v", email)
	}
	if webhook.Depth != 1 || webhook.InFlight != 0 || webhook.DroppedTotal != 0 {
		t.Fatalf("unattempted second sink hidden: %+v", webhook)
	}
	c.Observe("203.0.113.24", "fixture next block", time.Now())
	if row := digestQueueStatuses(t, c, time.Now())["records"]; row.Depth != 1 || row.InFlight != 0 || row.DroppedTotal != 0 {
		t.Fatalf("new records merged into detached digest: %+v", row)
	}
	unblock()
	<-done
	if sent != 1 {
		t.Fatalf("webhook attempts=%d, want 1 after email failure", sent)
	}
	rows = digestQueueStatuses(t, c, time.Now())
	if rows["email"].InFlight != 0 || rows["email"].DroppedTotal != 1 || rows["webhook"].Depth != 0 || rows["webhook"].InFlight != 0 || rows["webhook"].DroppedTotal != 0 {
		t.Fatalf("completed sink outcome: email=%+v webhook=%+v", rows["email"], rows["webhook"])
	}
}

func TestBlockDigestQueueGatingAndShutdown(t *testing.T) {
	calls := 0
	c := New(Options{Interval: time.Hour, SendOn: "customer", MinBlock: 1, EmailSink: func(string, string) error { calls++; return nil }})
	c.Observe("198.51.100.23", "smtp brute force", time.Now())
	stop := make(chan struct{})
	close(stop)
	c.Run(stop, nil)
	row := digestQueueStatuses(t, c, time.Now())["records"]
	if calls != 0 || row.Depth != 0 || row.InFlight != 0 || row.DroppedTotal != 0 {
		t.Fatalf("expected customer-only gating became queue failure: calls=%d row=%+v", calls, row)
	}
	c.Observe("203.0.113.24", "fixture customer block", time.Now())
	row = digestQueueStatuses(t, c, time.Now())["records"]
	if row.Depth != 1 || row.DroppedTotal != 0 || row.Reason != "consumer_stopped" {
		t.Fatalf("work retained after ticker shutdown hidden: %+v", row)
	}
	c.Flush()
	row = digestQueueStatuses(t, c, time.Now())["records"]
	if calls != 1 || row.Depth != 0 || row.InFlight != 0 || row.DroppedTotal != 0 || row.Status != "ok" {
		t.Fatalf("explicit final flush changed existing recovery: calls=%d row=%+v", calls, row)
	}
}
