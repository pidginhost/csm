package alert

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/obs"
	"github.com/pidginhost/csm/internal/queuehealth"
	bolt "go.etcd.io/bbolt"
)

const (
	phpanelQueueLimit      = 100000
	phpanelQuarantineLimit = 1000
)

var phpanelQueueBucket = []byte("findings")
var phpanelQuarantineBucket = []byte("quarantine")

type queuedPhpanelFinding struct {
	Finding   Finding   `json:"finding"`
	Timestamp time.Time `json:"timestamp"`
}

type quarantinedPhpanelFinding struct {
	Payload       []byte    `json:"payload"`
	Error         string    `json:"error"`
	QuarantinedAt time.Time `json:"quarantined_at"`
}

type phpanelDeliveryConfig struct {
	hostname      string
	url           string
	hmacSecret    string
	hmacSecretEnv string
}

type phpanelQueue struct {
	db         *bolt.DB
	cfgMu      sync.RWMutex
	cfg        phpanelDeliveryConfig
	wake       chan struct{}
	stop       chan struct{}
	done       chan struct{}
	drain      sync.Mutex
	retryMu    sync.Mutex
	retryAt    time.Time
	retryDelay time.Duration
	closed     bool
	mu         sync.Mutex
	mutation   sync.Mutex
	limit      int
	health     phpanelQueueHealth
}

var phpanelQueues = struct {
	sync.Mutex
	byState map[string]*phpanelQueue
}{byState: make(map[string]*phpanelQueue)}

func enqueuePhpanelFindings(cfg *config.Config, findings []Finding) error {
	queue, err := phpanelQueueForMode(cfg, false)
	if err != nil {
		return err
	}
	queued := make([]queuedPhpanelFinding, 0, len(findings))
	for _, finding := range findings {
		queued = append(queued, queuedPhpanelFinding{Finding: finding, Timestamp: time.Now().UTC()})
	}
	dropped, err := queue.enqueueBatch(queued)
	if err != nil {
		return fmt.Errorf("queueing phpanel webhook: %w", err)
	}
	select {
	case queue.wake <- struct{}{}:
	default:
	}
	if dropped > 0 {
		alertDispatchFailures.Add(float64(dropped))
		return fmt.Errorf("phpanel webhook queue reached %d entries and dropped %d oldest findings", phpanelQueueLimit, dropped)
	}
	return nil
}

// ConfigurePhpanelQueue opens and wakes the durable queue during daemon
// startup and safe config reloads. This lets persisted findings resume delivery
// without waiting for a new finding to arrive after a restart.
func ConfigurePhpanelQueue(cfg *config.Config) error {
	if cfg == nil || !cfg.Alerts.Webhook.Enabled || cfg.Alerts.Webhook.Type != "phpanel" {
		closePhpanelQueue(cfg)
		return nil
	}
	queue, err := phpanelQueueFor(cfg)
	if err != nil {
		return err
	}
	select {
	case queue.wake <- struct{}{}:
	default:
	}
	return nil
}

func closePhpanelQueue(cfg *config.Config) {
	if cfg == nil || cfg.StatePath == "" {
		return
	}
	statePath, err := filepath.Abs(cfg.StatePath)
	if err != nil {
		return
	}
	phpanelQueues.Lock()
	queue := phpanelQueues.byState[statePath]
	delete(phpanelQueues.byState, statePath)
	phpanelQueues.Unlock()
	if queue != nil {
		queue.close()
	}
}

func phpanelQueueFor(cfg *config.Config) (*phpanelQueue, error) {
	return phpanelQueueForMode(cfg, true)
}

func phpanelQueueForMode(cfg *config.Config, updateExisting bool) (*phpanelQueue, error) {
	if cfg.StatePath == "" {
		return nil, fmt.Errorf("phpanel webhook requires state_path for its durable queue")
	}
	statePath, err := filepath.Abs(cfg.StatePath)
	if err != nil {
		return nil, fmt.Errorf("resolving phpanel queue state path: %w", err)
	}
	phpanelQueues.Lock()
	defer phpanelQueues.Unlock()
	if queue := phpanelQueues.byState[statePath]; queue != nil {
		if updateExisting {
			queue.updateConfig(cfg)
		}
		return queue, nil
	}
	if mkdirErr := os.MkdirAll(statePath, 0o700); mkdirErr != nil {
		return nil, fmt.Errorf("creating phpanel queue state directory: %w", mkdirErr)
	}
	db, err := bolt.Open(filepath.Join(statePath, "phpanel-webhook.db"), 0o600, &bolt.Options{Timeout: 2 * time.Second})
	if err != nil {
		return nil, fmt.Errorf("opening phpanel webhook queue: %w", err)
	}
	queue, err := newPhpanelQueue(db, phpanelQueueLimit)
	if err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("creating phpanel webhook queue: %w", err)
	}
	queue.updateConfig(cfg)
	phpanelQueues.byState[statePath] = queue
	phpanelHealth.Lock()
	phpanelHealth.active[queue] = struct{}{}
	phpanelHealth.Unlock()
	obs.Go("phpanel-webhook-queue", queue.run)
	return queue, nil
}

func newPhpanelQueue(db *bolt.DB, limit int) (*phpanelQueue, error) {
	q := &phpanelQueue{
		db: db, limit: limit,
		wake: make(chan struct{}, 1), stop: make(chan struct{}), done: make(chan struct{}),
		health: phpanelQueueHealth{
			// Two normal drain intervals without completion warrant attention.
			stats: queuehealth.NewSharedCapacity(limit, time.Minute), pending: make(map[string]*phpanelWork),
		},
	}
	if err := db.Update(func(tx *bolt.Tx) error {
		if _, err := tx.CreateBucketIfNotExists(phpanelQueueBucket); err != nil {
			return err
		}
		_, err := tx.CreateBucketIfNotExists(phpanelQuarantineBucket)
		return err
	}); err != nil {
		return nil, err
	}
	now := time.Now()
	if err := db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(phpanelQueueBucket).ForEach(func(key, payload []byte) error {
			var item queuedPhpanelFinding
			queuedAt := now
			if err := json.Unmarshal(payload, &item); err == nil && !item.Timestamp.IsZero() && item.Timestamp.Before(now) {
				queuedAt = item.Timestamp
			}
			// Damaged or future timestamps supply no reliable elapsed age.
			// The record still enters normal delivery/quarantine processing.
			q.health.pending[string(key)] = &phpanelWork{ticket: q.health.stats.BeginAt(queuedAt, now)}
			return nil
		})
	}); err != nil {
		return nil, err
	}
	return q, nil
}

func (q *phpanelQueue) updateConfig(cfg *config.Config) {
	q.cfgMu.Lock()
	q.cfg = phpanelDeliveryConfig{
		hostname:      cfg.Hostname,
		url:           cfg.Alerts.Webhook.URL,
		hmacSecret:    cfg.Alerts.Webhook.HMACSecret,
		hmacSecretEnv: cfg.Alerts.Webhook.HMACSecretEnv,
	}
	q.cfgMu.Unlock()
	q.retryMu.Lock()
	q.retryAt = time.Time{}
	q.retryDelay = 0
	q.retryMu.Unlock()
}

func (q *phpanelQueue) enqueueBatch(items []queuedPhpanelFinding) (int, error) {
	if len(items) == 0 {
		return 0, nil
	}
	now := time.Now()
	work := make([]*phpanelWork, len(items))
	for i, item := range items {
		queuedAt := item.Timestamp
		if queuedAt.IsZero() || queuedAt.After(now) {
			queuedAt = now
		}
		work[i] = &phpanelWork{ticket: q.health.stats.BeginAt(queuedAt, now)}
		work[i].ticket.Start(now)
	}
	committed := false
	defer func() {
		if !committed {
			for _, entry := range work {
				q.discardWork(entry, time.Now())
			}
		}
	}()
	bodies := make([][]byte, 0, len(items))
	for _, item := range items {
		body, err := json.Marshal(item)
		if err != nil {
			q.health.enqueueFailed.Store(true)
			return 0, err
		}
		bodies = append(bodies, body)
	}
	q.mutation.Lock()
	defer q.mutation.Unlock()
	select {
	case <-q.stop:
		return 0, fmt.Errorf("phpanel webhook queue is stopped")
	default:
	}
	var added, evicted []string
	err := q.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(phpanelQueueBucket)
		count := queuedFindingCount(bucket) + len(bodies)
		for _, body := range bodies {
			seq, err := bucket.NextSequence()
			if err != nil {
				return err
			}
			var key [8]byte
			binary.BigEndian.PutUint64(key[:], seq)
			if err := bucket.Put(key[:], body); err != nil {
				return err
			}
			added = append(added, string(key[:]))
		}
		for count > q.limit {
			oldest, _ := bucket.Cursor().First()
			if oldest == nil {
				// The live span is empty, so the count came from somewhere
				// other than this bucket. Nothing is left to evict.
				break
			}
			evictedKey := string(oldest)
			if err := bucket.Delete(oldest); err != nil {
				return err
			}
			evicted = append(evicted, evictedKey)
			count--
		}
		return nil
	})
	if err != nil {
		q.health.enqueueFailed.Store(true)
		return 0, err
	}
	now = time.Now()
	for i, key := range added {
		work[i].ticket.Requeue(now)
		q.health.pending[key] = work[i]
	}
	for _, key := range evicted {
		entry := q.health.pending[key]
		delete(q.health.pending, key)
		switch {
		case entry == nil:
			// A record evicted from the queue file with no accounting cannot
			// be attributed to a caller; count the finding it carried as lost.
			phpanelHealth.losses.Lose(now, 1)
		case entry == q.health.active:
			entry.evicted = true
		default:
			q.discardWork(entry, now)
		}
	}
	q.health.enqueueFailed.Store(false)
	committed = true
	return len(evicted), nil
}

// queuedFindingCount returns the number of live entries without walking every
// page. Deliveries, quarantine, and overflow trimming only ever remove the
// current oldest entry, so live keys stay a contiguous span of the monotonic
// sequence numbers assigned by NextSequence; the count is that span.
func queuedFindingCount(bucket *bolt.Bucket) int {
	cursor := bucket.Cursor()
	firstKey, _ := cursor.First()
	if firstKey == nil {
		return 0
	}
	lastKey, _ := cursor.Last()
	// last >= first (bbolt key order) and the live span is bounded by
	// phpanelQueueLimit, so the difference always fits in an int.
	// #nosec G115 -- bounded span (<= phpanelQueueLimit); cannot overflow int.
	return int(binary.BigEndian.Uint64(lastKey)-binary.BigEndian.Uint64(firstKey)) + 1
}

func (q *phpanelQueue) run() {
	defer close(q.done)
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-q.wake:
			q.drainQueued()
		case <-ticker.C:
			q.drainQueued()
		case <-q.stop:
			return
		}
	}
}

func (q *phpanelQueue) drainQueued() {
	q.drain.Lock()
	defer q.drain.Unlock()
	q.retryMu.Lock()
	if time.Now().Before(q.retryAt) {
		q.retryMu.Unlock()
		return
	}
	q.retryMu.Unlock()
	for {
		select {
		case <-q.stop:
			return
		default:
		}
		key, payload, work, err := q.takeDelivery()
		if err != nil {
			fmt.Fprintf(os.Stderr, "alert: reading phpanel webhook queue: %v\n", err)
			alertDispatchFailures.Inc()
			return
		}
		if key == nil {
			return
		}
		if !q.deliverQueued(key, payload, work) {
			return
		}
	}
}

func (q *phpanelQueue) takeDelivery() ([]byte, []byte, *phpanelWork, error) {
	q.mutation.Lock()
	defer q.mutation.Unlock()
	var key, payload []byte
	err := q.db.View(func(tx *bolt.Tx) error {
		firstKey, value := tx.Bucket(phpanelQueueBucket).Cursor().First()
		if firstKey != nil {
			key = append([]byte(nil), firstKey...)
			payload = append([]byte(nil), value...)
		}
		return nil
	})
	q.health.readFailed.Store(err != nil)
	if err != nil || key == nil {
		return key, payload, nil, err
	}
	work := q.health.pending[string(key)]
	if work == nil {
		// The queue file outlives the process that wrote it. A record with no
		// accounting still has to be delivered, so it is adopted here.
		work = &phpanelWork{ticket: q.health.stats.Begin(time.Now())}
		q.health.pending[string(key)] = work
	}
	work.ticket.Start(time.Now())
	q.health.active = work
	return key, payload, work, nil
}

func (q *phpanelQueue) deliverQueued(key, payload []byte, work *phpanelWork) bool {
	sent, removed := false, false
	attempted := false
	defer func() {
		if attempted && !sent {
			q.health.sendFailed.Store(true)
		}
		q.finishDelivery(work, sent, removed)
	}()
	var item queuedPhpanelFinding
	if err := json.Unmarshal(payload, &item); err != nil {
		if quarantineErr := q.quarantineMalformed(key, payload, err); quarantineErr != nil {
			fmt.Fprintf(os.Stderr, "alert: quarantining malformed phpanel webhook: %v\n", quarantineErr)
			alertDispatchFailures.Inc()
			return false
		}
		fmt.Fprintf(os.Stderr, "alert: quarantined malformed phpanel webhook: %v\n", err)
		alertDispatchFailures.Inc()
		return true
	}
	q.cfgMu.RLock()
	delivery := q.cfg
	q.cfgMu.RUnlock()
	attempted = true
	if err := sendQueuedPhpanelWebhookFinding(delivery, item); err != nil {
		fmt.Fprintf(os.Stderr, "alert: phpanel webhook delivery failed: %v\n", err)
		alertDispatchFailures.Inc()
		q.recordRetryFailure()
		return false
	}
	sent = true
	q.health.sendFailed.Store(false)
	var err error
	removed, err = q.removeDelivered(key)
	if err != nil {
		fmt.Fprintf(os.Stderr, "alert: deleting delivered phpanel webhook: %v\n", err)
		alertDispatchFailures.Inc()
		return false
	}
	q.clearRetryFailure()
	return true
}

func (q *phpanelQueue) removeDelivered(key []byte) (bool, error) {
	q.mutation.Lock()
	defer q.mutation.Unlock()
	err := q.db.Update(func(tx *bolt.Tx) error { return tx.Bucket(phpanelQueueBucket).Delete(key) })
	q.health.removeFailed.Store(err != nil)
	if err != nil {
		return false, err
	}
	delete(q.health.pending, string(key))
	return true, nil
}

func (q *phpanelQueue) quarantineMalformed(key, payload []byte, decodeErr error) error {
	return q.quarantineMalformedWithLimit(key, payload, decodeErr, phpanelQuarantineLimit)
}

func (q *phpanelQueue) quarantineMalformedWithLimit(key, payload []byte, decodeErr error, limit int) error {
	if limit <= 0 {
		return fmt.Errorf("phpanel quarantine limit must be positive")
	}
	record, marshalErr := json.Marshal(quarantinedPhpanelFinding{
		Payload:       payload,
		Error:         decodeErr.Error(),
		QuarantinedAt: time.Now().UTC(),
	})
	if marshalErr != nil {
		return marshalErr
	}
	q.mutation.Lock()
	defer q.mutation.Unlock()
	removed := false
	updateErr := q.db.Update(func(tx *bolt.Tx) error {
		active := tx.Bucket(phpanelQueueBucket)
		current := active.Get(key)
		if current == nil {
			return nil
		}
		if !bytes.Equal(current, payload) {
			return fmt.Errorf("phpanel queue entry changed while being quarantined")
		}
		quarantine := tx.Bucket(phpanelQuarantineBucket)
		if quarantine.Get(key) == nil {
			count := quarantine.Stats().KeyN
			for count >= limit {
				oldest, _ := quarantine.Cursor().First()
				if oldest == nil {
					break
				}
				if err := quarantine.Delete(oldest); err != nil {
					return err
				}
				count--
			}
		}
		if err := quarantine.Put(key, record); err != nil {
			return err
		}
		if err := active.Delete(key); err != nil {
			return err
		}
		removed = true
		return nil
	})
	q.health.removeFailed.Store(updateErr != nil)
	if updateErr == nil && removed {
		work := q.health.pending[string(key)]
		delete(q.health.pending, string(key))
		switch {
		case work == nil:
			// Quarantined a record this process never accounted for.
			phpanelHealth.losses.Lose(time.Now(), 1)
		case work == q.health.active:
			work.evicted = true
		default:
			q.discardWork(work, time.Now())
		}
	}
	return updateErr
}

func (q *phpanelQueue) recordRetryFailure() {
	q.retryMu.Lock()
	defer q.retryMu.Unlock()
	if q.retryDelay == 0 {
		q.retryDelay = 30 * time.Second
	} else {
		q.retryDelay *= 2
		if q.retryDelay > 15*time.Minute {
			q.retryDelay = 15 * time.Minute
		}
	}
	q.retryAt = time.Now().Add(q.retryDelay)
}

func (q *phpanelQueue) clearRetryFailure() {
	q.retryMu.Lock()
	q.retryAt = time.Time{}
	q.retryDelay = 0
	q.retryMu.Unlock()
}

func (q *phpanelQueue) close() {
	q.mu.Lock()
	if q.closed {
		q.mu.Unlock()
		return
	}
	q.closed = true
	close(q.stop)
	q.mu.Unlock()
	<-q.done
	q.drain.Lock()
	q.mutation.Lock()
	phpanelHealth.Lock()
	delete(phpanelHealth.active, q)
	phpanelHealth.Unlock()
	for _, work := range q.health.pending {
		// These findings remain durable for a later start.
		work.ticket.Finish(time.Now())
	}
	clear(q.health.pending)
	_ = q.db.Close()
	q.mutation.Unlock()
	q.drain.Unlock()
}

func closePhpanelQueuesForTest() {
	ClosePhpanelQueues()
}

// ClosePhpanelQueues stops delivery workers and closes their durable databases.
func ClosePhpanelQueues() {
	phpanelQueues.Lock()
	queues := make([]*phpanelQueue, 0, len(phpanelQueues.byState))
	for _, queue := range phpanelQueues.byState {
		queues = append(queues, queue)
	}
	phpanelQueues.byState = make(map[string]*phpanelQueue)
	phpanelQueues.Unlock()
	for _, queue := range queues {
		queue.close()
	}
}

func phpanelQueueDepthForTest(statePath string) int {
	absolute, _ := filepath.Abs(statePath)
	phpanelQueues.Lock()
	queue := phpanelQueues.byState[absolute]
	phpanelQueues.Unlock()
	if queue == nil {
		return 0
	}
	depth := 0
	_ = queue.db.View(func(tx *bolt.Tx) error {
		depth = tx.Bucket(phpanelQueueBucket).Stats().KeyN
		return nil
	})
	return depth
}
