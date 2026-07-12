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
	dropped, err := queue.enqueueBatch(queued, phpanelQueueLimit)
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
	queue := &phpanelQueue{db: db, wake: make(chan struct{}, 1), stop: make(chan struct{}), done: make(chan struct{})}
	if err := db.Update(func(tx *bolt.Tx) error {
		if _, createErr := tx.CreateBucketIfNotExists(phpanelQueueBucket); createErr != nil {
			return createErr
		}
		_, createErr := tx.CreateBucketIfNotExists(phpanelQuarantineBucket)
		return createErr
	}); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("creating phpanel webhook queue: %w", err)
	}
	queue.updateConfig(cfg)
	phpanelQueues.byState[statePath] = queue
	obs.Go("phpanel-webhook-queue", queue.run)
	return queue, nil
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

func (q *phpanelQueue) enqueueBatch(items []queuedPhpanelFinding, limit int) (int, error) {
	if len(items) == 0 {
		return 0, nil
	}
	if limit <= 0 {
		return 0, fmt.Errorf("phpanel queue limit must be positive")
	}
	bodies := make([][]byte, 0, len(items))
	for _, item := range items {
		body, err := json.Marshal(item)
		if err != nil {
			return 0, err
		}
		bodies = append(bodies, body)
	}
	dropped := 0
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
		}
		for count > limit {
			trimCursor := bucket.Cursor()
			oldest, _ := trimCursor.First()
			if oldest == nil {
				break
			}
			if err := bucket.Delete(oldest); err != nil {
				return err
			}
			count--
			dropped++
		}
		return nil
	})
	return dropped, err
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
		// Stop draining promptly on shutdown. Undelivered findings are durable
		// and resume on the next start, so a healthy collector with a large
		// backlog must not keep close() blocked delivering the whole queue.
		select {
		case <-q.stop:
			return
		default:
		}
		var key []byte
		var payload []byte
		err := q.db.View(func(tx *bolt.Tx) error {
			cursor := tx.Bucket(phpanelQueueBucket).Cursor()
			firstKey, value := cursor.First()
			if firstKey == nil {
				return nil
			}
			key = append([]byte(nil), firstKey...)
			payload = append([]byte(nil), value...)
			return nil
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "alert: reading phpanel webhook queue: %v\n", err)
			alertDispatchFailures.Inc()
			return
		}
		if key == nil {
			return
		}
		var item queuedPhpanelFinding
		if err := json.Unmarshal(payload, &item); err != nil {
			if quarantineErr := q.quarantineMalformed(key, payload, err); quarantineErr != nil {
				fmt.Fprintf(os.Stderr, "alert: quarantining malformed phpanel webhook: %v\n", quarantineErr)
				alertDispatchFailures.Inc()
				return
			}
			fmt.Fprintf(os.Stderr, "alert: quarantined malformed phpanel webhook: %v\n", err)
			alertDispatchFailures.Inc()
			continue
		}
		q.cfgMu.RLock()
		delivery := q.cfg
		q.cfgMu.RUnlock()
		if err := sendQueuedPhpanelWebhookFinding(delivery, item); err != nil {
			fmt.Fprintf(os.Stderr, "alert: phpanel webhook delivery failed: %v\n", err)
			alertDispatchFailures.Inc()
			q.recordRetryFailure()
			return
		}
		if err := q.db.Update(func(tx *bolt.Tx) error {
			return tx.Bucket(phpanelQueueBucket).Delete(key)
		}); err != nil {
			fmt.Fprintf(os.Stderr, "alert: deleting delivered phpanel webhook: %v\n", err)
			alertDispatchFailures.Inc()
			return
		}
		q.clearRetryFailure()
	}
}

func (q *phpanelQueue) quarantineMalformed(key, payload []byte, decodeErr error) error {
	return q.quarantineMalformedWithLimit(key, payload, decodeErr, phpanelQuarantineLimit)
}

func (q *phpanelQueue) quarantineMalformedWithLimit(key, payload []byte, decodeErr error, limit int) error {
	if limit <= 0 {
		return fmt.Errorf("phpanel quarantine limit must be positive")
	}
	record, err := json.Marshal(quarantinedPhpanelFinding{
		Payload:       payload,
		Error:         decodeErr.Error(),
		QuarantinedAt: time.Now().UTC(),
	})
	if err != nil {
		return err
	}
	return q.db.Update(func(tx *bolt.Tx) error {
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
		return nil
	})
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
	_ = q.db.Close()
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
