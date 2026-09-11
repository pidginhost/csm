package alert

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/queuehealth"
	bolt "go.etcd.io/bbolt"
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

// Bypass admission to represent a boundary record without creating an orphaned
// ticket. Normal opens rebuild accounting for every persisted record.
func insertUntrackedPhpanelRecord(t *testing.T, q *phpanelQueue, payload []byte) []byte {
	t.Helper()
	var key [8]byte
	if err := q.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(phpanelQueueBucket)
		seq, err := b.NextSequence()
		if err != nil {
			return err
		}
		binary.BigEndian.PutUint64(key[:], seq)
		return b.Put(key[:], payload)
	}); err != nil {
		t.Fatal(err)
	}
	return key[:]
}

func TestPhpanelQueueHealthSurvivesRecordsWithoutAccounting(t *testing.T) {
	q := newUnregisteredPhpanelQueue(t, phpanelDeliveryConfig{}, phpanelQueueLimit)
	now := time.Now()
	item := queuedPhpanelFinding{Finding: Finding{Check: "orphan"}, Timestamp: now.Add(-2 * time.Minute)}
	body, err := json.Marshal(item)
	if err != nil {
		t.Fatal(err)
	}
	insertUntrackedPhpanelRecord(t, q, body)
	key, payload, work, err := q.takeDelivery()
	if err != nil || key == nil || work == nil || len(payload) == 0 {
		t.Fatalf("a record with no accounting was not taken for delivery: key=%q work=%v err=%v", key, work, err)
	}
	if status := phpanelHealthStatus(t, q, time.Now()); status.InFlight != 1 || status.Depth != 0 {
		t.Fatalf("adopted record is not in flight: %+v", status)
	}
	q.finishDelivery(work, false, false)
	if status := phpanelHealthStatus(t, q, time.Now()); status.Depth != 1 || status.InFlight != 0 || status.DroppedTotal != 0 || status.LagSeconds < 120 || status.Reason != "backlog_lag" {
		t.Fatalf("adopted retry lost its persisted waiting age: %+v", status)
	}
	key, _, work, err = q.takeDelivery()
	if err != nil || work == nil {
		t.Fatalf("take retry: work=%v err=%v", work, err)
	}
	removed, err := q.removeDelivered(key)
	if err != nil || !removed {
		t.Fatalf("remove delivered record: removed=%v err=%v", removed, err)
	}
	q.finishDelivery(work, true, removed)
	if status := phpanelHealthStatus(t, q, time.Now()); status.Depth != 0 || status.InFlight != 0 || status.DroppedTotal != 0 || len(q.health.pending) != 0 || phpanelActiveDepth(t, q) != 0 {
		t.Fatalf("adopted record did not settle exactly once: %+v", status)
	}
}

func TestPhpanelQueueHealthCountsEvictedRecordsWithoutAccounting(t *testing.T) {
	q := newUnregisteredPhpanelQueue(t, phpanelDeliveryConfig{}, 1)
	insertUntrackedPhpanelRecord(t, q, []byte(`{"finding":{"check":"first"}}`))
	// A record with no ticket can only be counted in the process-wide row,
	// which is also where losses from replaced queues live.
	before := PhpanelQueueStatus(time.Now()).DroppedTotal
	if dropped, err := q.enqueueBatch([]queuedPhpanelFinding{{Finding: Finding{Check: "second"}, Timestamp: time.Now()}}); err != nil || dropped != 1 {
		t.Fatalf("overflow enqueue: dropped=%d err=%v", dropped, err)
	}
	if got := PhpanelQueueStatus(time.Now()).DroppedTotal; got != before+1 {
		t.Fatalf("an evicted record with no accounting vanished: dropped=%d, want %d", got, before+1)
	}
	if got := phpanelHealthStatus(t, q, time.Now()); got.Depth != 1 || got.InFlight != 0 || len(q.health.pending) != 1 || phpanelActiveDepth(t, q) != 1 {
		t.Fatalf("eviction left unmatched accounting: %+v", got)
	}
}

func TestPhpanelQueueHealthQuarantinesUntrackedRecords(t *testing.T) {
	for _, adopted := range []bool{false, true} {
		q := newUnregisteredPhpanelQueue(t, phpanelDeliveryConfig{}, 1)
		payload := []byte(`{"finding":`)
		key := insertUntrackedPhpanelRecord(t, q, payload)
		before := PhpanelQueueStatus(time.Now()).DroppedTotal
		if adopted {
			q.drainQueued()
		} else if err := q.quarantineMalformed(key, payload, errors.New("invalid record")); err != nil {
			t.Fatal(err)
		}
		// An empty drain and repeated quarantine must not settle or count the
		// already discarded record a second time.
		q.drainQueued()
		if err := q.quarantineMalformed(key, payload, errors.New("invalid record")); err != nil {
			t.Fatal(err)
		}
		if got := PhpanelQueueStatus(time.Now()).DroppedTotal; got != before+1 {
			t.Fatalf("quarantine loss count = %d, want %d (adopted=%v)", got, before+1, adopted)
		}
		wantLocalLoss := uint64(0)
		if adopted {
			wantLocalLoss = 1
		}
		if got := phpanelHealthStatus(t, q, time.Now()); got.Depth != 0 || got.InFlight != 0 || got.DroppedTotal != wantLocalLoss || len(q.health.pending) != 0 || phpanelActiveDepth(t, q) != 0 {
			t.Fatalf("quarantined record left unmatched accounting: %+v (adopted=%v)", got, adopted)
		}
	}
}
