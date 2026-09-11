package alert

import (
	"crypto/rand"
	"errors"
	"io"
	"net/http"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/config"
	bolt "go.etcd.io/bbolt"
	berrors "go.etcd.io/bbolt/errors"
)

func TestPhpanelQueueHealthOverflowAndFullCapacity(t *testing.T) {
	q := newUnregisteredPhpanelQueue(t, phpanelDeliveryConfig{}, 2)
	now := time.Now()
	items := make([]queuedPhpanelFinding, 4)
	for i := range items {
		items[i] = queuedPhpanelFinding{Finding: Finding{Check: "pending"}, Timestamp: now}
	}
	if dropped, err := q.enqueueBatch(items); err != nil || dropped != 2 {
		t.Fatalf("enqueue: dropped=%d err=%v", dropped, err)
	}
	status := phpanelHealthStatus(t, q, now.Add(31*time.Second))
	if status.Status != "degraded" || status.Reason != "queue_full" || status.Depth != 2 || status.InFlight != 0 || status.Capacity != 2 || status.DroppedTotal != 2 {
		t.Fatalf("full queue status = %+v", status)
	}
}

func TestPhpanelQueueHealthActiveEvictionWaitsForDelivery(t *testing.T) {
	for _, fails := range []bool{false, true} {
		name := "delivered"
		if fails {
			name = "failed"
		}
		t.Run(name, func(t *testing.T) {
			entered, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
			calls := 0
			restore := SetWebhookTransportForTest(phpanelHealthTransport(func(r *http.Request) (*http.Response, error) {
				calls++
				if calls == 1 {
					close(entered)
					<-release
					if fails {
						return nil, errors.New("collector unavailable")
					}
				}
				return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("")), Request: r}, nil
			}))
			t.Cleanup(restore)
			q := newUnregisteredPhpanelQueue(t, phpanelDeliveryConfig{hostname: "host", url: "https://panel.invalid/findings", hmacSecret: rand.Text()}, 1)
			item := []queuedPhpanelFinding{{Finding: Finding{Check: "pending"}, Timestamp: time.Now()}}
			if _, err := q.enqueueBatch(item); err != nil {
				t.Fatal(err)
			}
			go func() { defer close(done); q.drainQueued() }()
			finish := sync.OnceFunc(func() { close(release); <-done })
			defer finish()
			select {
			case <-entered:
			case <-time.After(2 * time.Second):
				t.Fatal("delivery did not start")
			}
			if dropped, err := q.enqueueBatch(item); err != nil || dropped != 1 {
				t.Fatalf("active eviction: dropped=%d err=%v", dropped, err)
			}
			status := phpanelHealthStatus(t, q, time.Now())
			if status.Depth != 1 || status.InFlight != 1 || status.DroppedTotal != 0 {
				t.Fatalf("active eviction counted loss before delivery finished: %+v", status)
			}
			finish()
			status = phpanelHealthStatus(t, q, time.Now())
			if fails {
				if status.Depth != 1 || status.InFlight != 0 || status.DroppedTotal != 1 || status.Reason != "delivery_failed" {
					t.Fatalf("failed evicted send = %+v", status)
				}
				q.clearRetryFailure()
				q.drainQueued()
				status = phpanelHealthStatus(t, q, time.Now())
				if status.Depth != 0 || status.InFlight != 0 || status.DroppedTotal != 1 || status.Status != "ok" {
					t.Fatalf("replacement delivery did not recover: %+v", status)
				}
			} else if status.Depth != 0 || status.InFlight != 0 || status.DroppedTotal != 0 || status.Status != "ok" {
				t.Fatalf("successful evicted send counted as loss: %+v", status)
			}
		})
	}
}

func TestPhpanelQueueHealthRespondsWhileDatabaseWriteWaits(t *testing.T) {
	q := newUnregisteredPhpanelQueue(t, phpanelDeliveryConfig{}, phpanelQueueLimit)
	tx, err := q.db.Begin(true)
	if err != nil {
		t.Fatal(err)
	}
	release := sync.OnceFunc(func() {
		if err := tx.Rollback(); err != nil {
			t.Error(err)
		}
	})
	defer release()
	result := make(chan error, 1)
	go func() {
		_, err := q.enqueueBatch([]queuedPhpanelFinding{{Finding: Finding{Check: "pending"}, Timestamp: time.Now()}})
		result <- err
	}()
	defer func() {
		release()
		if err := <-result; err != nil {
			t.Errorf("write after releasing database lock: %v", err)
		}
		status := phpanelHealthStatus(t, q, time.Now())
		if status.Depth != 1 || status.InFlight != 0 || status.DroppedTotal != 0 {
			t.Errorf("released write status = %+v", status)
		}
	}()
	deadline := time.Now().Add(2 * time.Second)
	for {
		status := phpanelHealthStatus(t, q, time.Now().Add(2*time.Minute))
		if status.InFlight == 1 {
			if status.Depth != 0 || status.Status != "degraded" || status.Reason != "processing_lag" || status.DroppedTotal != 0 {
				t.Fatalf("blocked write status = %+v", status)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("blocked persistence never became visible")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestPhpanelQueueHealthDatabaseFailureKeepsCommittedBacklog(t *testing.T) {
	restore := SetWebhookTransportForTest(phpanelHealthTransport(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("")), Request: r}, nil
	}))
	t.Cleanup(restore)
	q := newUnregisteredPhpanelQueue(t, phpanelDeliveryConfig{url: "https://panel.invalid/findings", hmacSecret: rand.Text()}, 2)
	item := queuedPhpanelFinding{Finding: Finding{Check: "pending"}, Timestamp: time.Now()}
	if _, err := q.enqueueBatch([]queuedPhpanelFinding{item}); err != nil {
		t.Fatal(err)
	}
	path := q.db.Path()
	if err := q.db.Close(); err != nil {
		t.Fatal(err)
	}
	q.drainQueued()
	if _, err := q.enqueueBatch([]queuedPhpanelFinding{item, item}); !errors.Is(err, berrors.ErrDatabaseNotOpen) {
		t.Fatalf("write to closed database: %v", err)
	}
	status := phpanelHealthStatus(t, q, time.Now())
	if status.Depth != 1 || status.InFlight != 0 || status.DroppedTotal != 2 || status.Reason != "spool_io" {
		t.Fatalf("failed database operation changed committed backlog: %+v", status)
	}
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	q.db = db
	if _, err := q.enqueueBatch([]queuedPhpanelFinding{item}); err != nil {
		t.Fatal(err)
	}
	if status := phpanelHealthStatus(t, q, time.Now()); status.Reason != "spool_io" || status.Depth != 2 {
		t.Fatalf("successful write hid an unrecovered read failure: %+v", status)
	}
	q.drainQueued()
	if status := phpanelHealthStatus(t, q, time.Now()); status.Status != "ok" || status.Depth != 0 || status.InFlight != 0 || status.DroppedTotal != 2 {
		t.Fatalf("database recovery lost counts or retained work: %+v", status)
	}
}

func TestPhpanelQueueHealthAcknowledgedOverflowIsNotLoss(t *testing.T) {
	for _, retryFails := range []bool{false, true} {
		name := "waiting"
		if retryFails {
			name = "failed_retry"
		}
		t.Run(name, func(t *testing.T) {
			q := newUnregisteredPhpanelQueue(t, phpanelDeliveryConfig{url: "https://panel.invalid/findings", hmacSecret: rand.Text()}, 1)
			item := []queuedPhpanelFinding{{Finding: Finding{Check: "pending"}, Timestamp: time.Now()}}
			path := q.db.Path()
			calls := 0
			restore := SetWebhookTransportForTest(phpanelHealthTransport(func(r *http.Request) (*http.Response, error) {
				calls++
				if calls == 1 {
					if err := q.db.Close(); err != nil {
						t.Fatal(err)
					}
				} else if calls == 2 && retryFails {
					if dropped, err := q.enqueueBatch(item); err != nil || dropped != 1 {
						t.Fatalf("evict acknowledged retry: dropped=%d err=%v", dropped, err)
					}
					return nil, errors.New("collector unavailable on retry")
				}
				return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("")), Request: r}, nil
			}))
			t.Cleanup(restore)
			if _, err := q.enqueueBatch(item); err != nil {
				t.Fatal(err)
			}
			q.drainQueued()
			if status := phpanelHealthStatus(t, q, time.Now()); calls != 1 || status.Depth != 1 || status.InFlight != 0 || status.DroppedTotal != 0 || status.Reason != "spool_io" {
				t.Fatalf("acknowledged record was not retained after delete failure: calls=%d status=%+v", calls, status)
			}
			db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: time.Second})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = db.Close() })
			q.db = db
			if retryFails {
				q.drainQueued()
				if calls != 2 {
					t.Fatalf("retry did not run: calls=%d", calls)
				}
			} else if dropped, err := q.enqueueBatch(item); err != nil || dropped != 1 {
				t.Fatalf("evict acknowledged record: dropped=%d err=%v", dropped, err)
			}
			if status := phpanelHealthStatus(t, q, time.Now()); status.Depth != 1 || status.InFlight != 0 || status.DroppedTotal != 0 {
				t.Fatalf("collector-acknowledged finding counted as lost: %+v", status)
			}
			q.clearRetryFailure()
			q.drainQueued()
			if status := phpanelHealthStatus(t, q, time.Now()); status.Depth != 0 || status.InFlight != 0 || status.DroppedTotal != 0 || status.Status != "ok" {
				t.Fatalf("replacement delivery did not recover: %+v", status)
			}
		})
	}
}

func TestPhpanelQueueHealthAbnormalSendRetainsDurableWork(t *testing.T) {
	for _, exits := range []bool{false, true} {
		name := "panic"
		if exits {
			name = "goexit"
		}
		t.Run(name, func(t *testing.T) {
			restore := SetWebhookTransportForTest(phpanelHealthTransport(func(*http.Request) (*http.Response, error) {
				if exits {
					runtime.Goexit()
				}
				panic("sender failed")
			}))
			t.Cleanup(restore)
			q := newUnregisteredPhpanelQueue(t, phpanelDeliveryConfig{url: "https://panel.invalid/findings", hmacSecret: rand.Text()}, 2)
			if _, err := q.enqueueBatch([]queuedPhpanelFinding{{Finding: Finding{Check: "pending"}, Timestamp: time.Now()}}); err != nil {
				t.Fatal(err)
			}
			done := make(chan any, 1)
			go func() {
				defer func() { done <- recover() }()
				q.drainQueued()
			}()
			select {
			case recovered := <-done:
				if !exits && recovered != "sender failed" {
					t.Fatalf("sender panic changed: %v", recovered)
				}
				if exits && recovered != nil {
					t.Fatalf("Goexit path panicked: %v", recovered)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("abnormal send stranded queue ownership")
			}
			status := phpanelHealthStatus(t, q, time.Now())
			if status.Depth != 1 || status.InFlight != 0 || status.DroppedTotal != 0 || status.Reason != "delivery_failed" {
				t.Fatalf("abnormal send lost durable work or retained ownership: %+v", status)
			}
		})
	}
}

func TestPhpanelQueueHealthConcurrentAdmissionAndClose(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	restore := SetWebhookTransportForTest(phpanelHealthTransport(func(r *http.Request) (*http.Response, error) {
		close(entered)
		<-release
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("")), Request: r}, nil
	}))
	t.Cleanup(restore)
	q := newUnregisteredPhpanelQueue(t, phpanelDeliveryConfig{url: "https://panel.invalid/findings", hmacSecret: rand.Text()}, 128)
	path := q.db.Path()
	item := []queuedPhpanelFinding{{Finding: Finding{Check: "pending"}, Timestamp: time.Now()}}
	if _, err := q.enqueueBatch(item); err != nil {
		t.Fatal(err)
	}
	go q.run()
	q.wake <- struct{}{}
	closeRequested, closed := make(chan struct{}), make(chan struct{})
	go func() { <-closeRequested; q.close(); close(closed) }()
	requestClose := sync.OnceFunc(func() { close(closeRequested) })
	releaseSend := sync.OnceFunc(func() { close(release) })
	defer func() { requestClose(); releaseSend(); <-closed }()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("delivery did not start")
	}
	const callers = 64
	start := make(chan struct{})
	results := make(chan error, callers)
	for range callers {
		go func() { <-start; _, err := q.enqueueBatch(item); results <- err }()
	}
	close(start)
	requestClose()
	<-q.stop
	if status := phpanelHealthStatus(t, q, time.Now()); status.InFlight < 1 {
		t.Fatalf("close hid the still-running send: %+v", status)
	}
	releaseSend()
	accepted, refused := 0, 0
	for range callers {
		if err := <-results; err == nil {
			accepted++
		} else {
			if !strings.Contains(err.Error(), "stopped") {
				t.Errorf("unexpected admission failure: %v", err)
			}
			refused++
		}
	}
	<-closed
	status := phpanelHealthStatus(t, q, time.Now())
	if status.Depth != 0 || status.InFlight != 0 || status.DroppedTotal != uint64(refused) {
		t.Fatalf("closed queue accounting = %+v, accepted=%d refused=%d", status, accepted, refused)
	}
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.View(func(tx *bolt.Tx) error {
		if got := tx.Bucket(phpanelQueueBucket).Stats().KeyN; got != accepted {
			t.Errorf("persisted backlog = %d, want %d accepted records", got, accepted)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestPhpanelQueueHealthReloadsBacklogWithoutResettingLoss(t *testing.T) {
	t.Cleanup(closePhpanelQueuesForTest)
	cfg := &config.Config{StatePath: t.TempDir()}
	q, openErr := phpanelQueueFor(cfg)
	if openErr != nil {
		t.Fatal(openErr)
	}
	baseline := PhpanelQueueStatus(time.Now()).DroppedTotal
	now := time.Now()
	if _, err := q.enqueueBatch([]queuedPhpanelFinding{{Finding: Finding{Check: "pending"}, Timestamp: now.Add(-20 * time.Second)}}); err != nil {
		t.Fatal(err)
	}
	if _, err := q.enqueueBatch([]queuedPhpanelFinding{{Timestamp: time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)}}); err == nil {
		t.Fatal("invalid finding did not fail")
	}
	if err := ConfigurePhpanelQueue(cfg); err != nil {
		t.Fatal(err)
	}
	status := PhpanelQueueStatus(now)
	if status.Depth != 0 || status.InFlight != 0 || status.Capacity != 0 || status.DroppedTotal != baseline+1 {
		t.Fatalf("disabled queue retained work or lost counters: %+v", status)
	}
	q, openErr = phpanelQueueFor(cfg)
	if openErr != nil {
		t.Fatal(openErr)
	}
	status = PhpanelQueueStatus(now)
	if status.Depth != 1 || status.InFlight != 0 || status.Capacity != phpanelQueueLimit || status.DroppedTotal != baseline+1 || status.LagSeconds != 20 {
		t.Fatalf("reopened queue lost persisted age or counters: %+v", status)
	}
	if depth := phpanelActiveDepth(t, q); depth != 1 {
		t.Fatalf("shutdown discarded durable backlog: %d", depth)
	}
}

func TestPhpanelQueueHealthArchiveCountsMalformedFindingOnce(t *testing.T) {
	q := newUnregisteredPhpanelQueue(t, phpanelDeliveryConfig{}, 2)
	for range 3 {
		if _, err := q.enqueueBatch([]queuedPhpanelFinding{{Finding: Finding{Check: "seed"}, Timestamp: time.Now()}}); err != nil {
			t.Fatal(err)
		}
		var key []byte
		payload := []byte("invalid json")
		if err := q.db.Update(func(tx *bolt.Tx) error {
			bucket := tx.Bucket(phpanelQueueBucket)
			k, _ := bucket.Cursor().First()
			key = append([]byte(nil), k...)
			return bucket.Put(key, payload)
		}); err != nil {
			t.Fatal(err)
		}
		if err := q.quarantineMalformedWithLimit(key, payload, errors.New("malformed finding"), 1); err != nil {
			t.Fatal(err)
		}
	}
	status := phpanelHealthStatus(t, q, time.Now())
	if status.Depth != 0 || status.InFlight != 0 || status.DroppedTotal != 3 || status.Reason != "dropped_work" {
		t.Fatalf("malformed/archive accounting = %+v", status)
	}
	if depth := phpanelQuarantineDepthForTest(t, q); depth != 1 {
		t.Fatalf("archive depth = %d, want bounded history of one", depth)
	}
}

func TestPhpanelQueueHealthMalformedRecordDoesNotInventDeliveryFailure(t *testing.T) {
	q := newUnregisteredPhpanelQueue(t, phpanelDeliveryConfig{url: "https://panel.invalid/findings", hmacSecret: rand.Text()}, 2)
	if _, err := q.enqueueBatch([]queuedPhpanelFinding{{Finding: Finding{Check: "seed"}, Timestamp: time.Now()}}); err != nil {
		t.Fatal(err)
	}
	if err := q.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(phpanelQueueBucket)
		key, _ := bucket.Cursor().First()
		return bucket.Put(key, []byte("invalid json"))
	}); err != nil {
		t.Fatal(err)
	}
	calls := 0
	restore := SetWebhookTransportForTest(phpanelHealthTransport(func(*http.Request) (*http.Response, error) {
		calls++
		return nil, errors.New("unexpected network request")
	}))
	t.Cleanup(restore)
	q.drainQueued()
	if calls != 0 || phpanelActiveDepth(t, q) != 0 || phpanelQuarantineDepthForTest(t, q) != 1 {
		t.Fatalf("malformed record did not move to archive without delivery: calls=%d", calls)
	}
	status := phpanelHealthStatus(t, q, time.Now().Add(time.Minute))
	if status.Status != "ok" || status.Reason != "" || status.Depth != 0 || status.InFlight != 0 || status.DroppedTotal != 1 || status.RecentDrops != 0 {
		t.Fatalf("archived record left a false delivery failure: %+v", status)
	}
}
