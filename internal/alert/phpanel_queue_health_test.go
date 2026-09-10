package alert

import (
	"crypto/rand"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/queuehealth"
)

func phpanelHealthStatus(t *testing.T, q *phpanelQueue, now time.Time) queuehealth.Status {
	t.Helper()
	source, ok := any(q).(interface {
		QueueStatuses(time.Time) map[string]queuehealth.Status
	})
	if !ok {
		t.Fatal("durable panel webhook queue does not expose queue health")
	}
	result := make(chan map[string]queuehealth.Status, 1)
	go func() { result <- source.QueueStatuses(now) }()
	var statuses map[string]queuehealth.Status
	select {
	case statuses = <-result:
	case <-time.After(2 * time.Second):
		t.Fatal("queue health waited for database or delivery I/O")
	}
	status, ok := statuses["spool"]
	if !ok || len(statuses) != 1 {
		t.Fatalf("panel queue health lacks its single spool row: %v", statuses)
	}
	return status
}

func TestPhpanelQueueHealthRefusesAdmissionAfterStop(t *testing.T) {
	q := newUnregisteredPhpanelQueue(t, phpanelDeliveryConfig{}, phpanelQueueLimit)
	item := []queuedPhpanelFinding{{Finding: Finding{Check: "pending"}, Timestamp: time.Now()}}
	if _, err := q.enqueueBatch(item); err != nil {
		t.Fatal(err)
	}
	close(q.stop)
	if _, err := q.enqueueBatch(item); err == nil {
		t.Fatal("stopped queue accepted late work")
	}
	if depth := phpanelActiveDepth(t, q); depth != 1 {
		t.Fatalf("late enqueue changed durable backlog: depth=%d", depth)
	}
	status := phpanelHealthStatus(t, q, time.Now())
	if status.Depth != 1 || status.InFlight != 0 || status.DroppedTotal != 1 {
		t.Fatalf("late enqueue status = %+v", status)
	}
}

func TestPhpanelQueueHealthRetainsDurableWaitingAge(t *testing.T) {
	q := newUnregisteredPhpanelQueue(t, phpanelDeliveryConfig{}, phpanelQueueLimit)
	now := time.Now()
	items := []queuedPhpanelFinding{
		{Finding: Finding{Check: "first"}, Timestamp: now.Add(-20 * time.Second)},
		{Finding: Finding{Check: "second"}, Timestamp: now.Add(-10 * time.Second)},
	}
	if dropped, err := q.enqueueBatch(items); err != nil || dropped != 0 {
		t.Fatalf("enqueue: dropped=%d err=%v", dropped, err)
	}
	status := phpanelHealthStatus(t, q, now)
	if status.Status != "ok" || status.Depth != 2 || status.InFlight != 0 || status.Capacity != phpanelQueueLimit || status.DroppedTotal != 0 || status.LagSeconds != 20 {
		t.Fatalf("queued status = %+v, want two records, oldest 20 seconds", status)
	}
	status = phpanelHealthStatus(t, q, now.Add(time.Minute))
	if status.Status != "degraded" || status.Reason != "backlog_lag" || status.LagSeconds != 80 {
		t.Fatalf("stalled durable backlog = %+v", status)
	}
}

func TestPhpanelQueueHealthCountsUncommittedBatchFailure(t *testing.T) {
	q := newUnregisteredPhpanelQueue(t, phpanelDeliveryConfig{}, phpanelQueueLimit)
	items := []queuedPhpanelFinding{
		{Finding: Finding{Check: "first"}, Timestamp: time.Now()},
		{Finding: Finding{Check: "invalid"}, Timestamp: time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)},
	}
	if _, err := q.enqueueBatch(items); err == nil {
		t.Fatal("invalid batch must fail before committing either record")
	}
	if depth := phpanelActiveDepth(t, q); depth != 0 {
		t.Fatalf("failed atomic batch persisted %d records", depth)
	}
	status := phpanelHealthStatus(t, q, time.Now())
	if status.Depth != 0 || status.InFlight != 0 || status.DroppedTotal != 2 {
		t.Fatalf("failed batch status = %+v, want two lost findings and no pending work", status)
	}
}

type phpanelHealthTransport func(*http.Request) (*http.Response, error)

func (f phpanelHealthTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestPhpanelQueueHealthKeepsFailedRetryPending(t *testing.T) {
	fail := true
	restore := SetWebhookTransportForTest(phpanelHealthTransport(func(r *http.Request) (*http.Response, error) {
		if fail {
			return nil, errors.New("collector unavailable")
		}
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("")), Request: r}, nil
	}))
	t.Cleanup(restore)
	q := newUnregisteredPhpanelQueue(t, phpanelDeliveryConfig{hostname: "host", url: "https://panel.invalid/findings", hmacSecret: rand.Text()}, phpanelQueueLimit)
	now := time.Now()
	if _, err := q.enqueueBatch([]queuedPhpanelFinding{{Finding: Finding{Check: "pending"}, Timestamp: now.Add(-20 * time.Second)}}); err != nil {
		t.Fatal(err)
	}
	q.drainQueued()
	status := phpanelHealthStatus(t, q, now.Add(time.Second))
	if status.Status != "degraded" || status.Reason != "delivery_failed" || status.Depth != 1 || status.InFlight != 0 || status.DroppedTotal != 0 || status.LagSeconds != 21 {
		t.Fatalf("retry status = %+v, want the original durable record still waiting", status)
	}
	q.drainQueued()
	status = phpanelHealthStatus(t, q, now.Add(2*time.Second))
	if status.Depth != 1 || status.InFlight != 0 || status.DroppedTotal != 0 || status.LagSeconds != 22 {
		t.Fatalf("backoff changed ownership or age: %+v", status)
	}
	fail = false
	q.clearRetryFailure()
	q.drainQueued()
	status = phpanelHealthStatus(t, q, time.Now())
	if status.Status != "ok" || status.Depth != 0 || status.InFlight != 0 || status.DroppedTotal != 0 {
		t.Fatalf("successful retry did not recover: %+v", status)
	}
}

func TestPhpanelQueueHealthSurvivesBlockedDelivery(t *testing.T) {
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	restore := SetWebhookTransportForTest(phpanelHealthTransport(func(r *http.Request) (*http.Response, error) {
		close(entered)
		<-release
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("")), Request: r}, nil
	}))
	t.Cleanup(restore)
	q := newUnregisteredPhpanelQueue(t, phpanelDeliveryConfig{hostname: "host", url: "https://panel.invalid/findings", hmacSecret: rand.Text()}, phpanelQueueLimit)
	if _, err := q.enqueueBatch([]queuedPhpanelFinding{{Finding: Finding{Check: "pending"}, Timestamp: time.Now()}}); err != nil {
		t.Fatal(err)
	}
	go func() {
		defer close(done)
		q.drainQueued()
	}()
	defer func() { close(release); <-done }()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("delivery did not start")
	}
	status := phpanelHealthStatus(t, q, time.Now().Add(2*time.Minute))
	if status.Status != "degraded" || status.Reason != "processing_lag" || status.Depth != 0 || status.InFlight != 1 || status.ProcessingSeconds < 120 || status.DroppedTotal != 0 {
		t.Fatalf("blocked delivery was hidden: %+v", status)
	}
}
