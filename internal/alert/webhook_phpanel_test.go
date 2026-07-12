package alert

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/config"
	bolt "go.etcd.io/bbolt"
)

func TestSendPhpanelWebhook_SignsBody(t *testing.T) {
	secret := "panel-shared-secret"
	var requests int32
	var capturedSig, capturedBody string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requests, 1)
		capturedSig = r.Header.Get("X-CSM-Signature")
		body, _ := io.ReadAll(r.Body)
		capturedBody = string(body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := &config.Config{Hostname: "host"}
	cfg.Alerts.Webhook.Enabled = true
	cfg.Alerts.Webhook.Type = "phpanel"
	cfg.Alerts.Webhook.URL = srv.URL
	cfg.Alerts.Webhook.HMACSecret = secret
	cfg.Alerts.Webhook.PerFinding = true

	finding := Finding{Check: "test", Severity: High, Message: "x"}
	if err := SendPhpanelWebhookFinding(cfg, finding); err != nil {
		t.Fatal(err)
	}
	if atomic.LoadInt32(&requests) != 1 {
		t.Fatalf("expected 1 request, got %d", requests)
	}

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(capturedBody))
	want := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	if capturedSig != want {
		t.Fatalf("expected sig %s, got %s", want, capturedSig)
	}
	if !strings.Contains(capturedBody, `"check":"test"`) {
		t.Fatalf("body should embed finding JSON, got %s", capturedBody)
	}
	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(capturedBody), &parsed); err != nil {
		t.Fatal(err)
	}
	if _, ok := parsed["finding"]; !ok {
		t.Fatalf("expected payload to wrap finding under 'finding' key, got %v", parsed)
	}
}

func TestSendPhpanelWebhook_EnvSecretOverridesInlineSecret(t *testing.T) {
	t.Setenv("CSM_PHPANEL_HMAC_TEST", "env-secret")
	var capturedSig, capturedBody string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedSig = r.Header.Get("X-CSM-Signature")
		body, _ := io.ReadAll(r.Body)
		capturedBody = string(body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := &config.Config{Hostname: "host"}
	cfg.Alerts.Webhook.URL = srv.URL
	cfg.Alerts.Webhook.HMACSecret = "inline-secret"
	cfg.Alerts.Webhook.HMACSecretEnv = "CSM_PHPANEL_HMAC_TEST"

	if err := SendPhpanelWebhookFinding(cfg, Finding{Check: "test", Severity: High}); err != nil {
		t.Fatal(err)
	}

	mac := hmac.New(sha256.New, []byte("env-secret"))
	mac.Write([]byte(capturedBody))
	want := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	if capturedSig != want {
		t.Fatalf("expected env-secret signature %s, got %s", want, capturedSig)
	}
}

func TestSendPhpanelWebhook_NoSecretIsError(t *testing.T) {
	cfg := &config.Config{Hostname: "h"}
	cfg.Alerts.Webhook.URL = "http://example.invalid"
	finding := Finding{Check: "x", Severity: High}
	if err := SendPhpanelWebhookFinding(cfg, finding); err == nil {
		t.Fatal("expected error when HMAC secret is unset")
	}
}

func TestSendPhpanelWebhook_4xxReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()
	cfg := &config.Config{Hostname: "h"}
	cfg.Alerts.Webhook.URL = srv.URL
	cfg.Alerts.Webhook.HMACSecret = "s"
	if err := SendPhpanelWebhookFinding(cfg, Finding{Check: "x", Severity: High}); err == nil {
		t.Fatal("expected error on HTTP 403")
	}
}

func TestDispatchPhpanelWebhookAlwaysUsesSignedPerFinding(t *testing.T) {
	t.Cleanup(closePhpanelQueuesForTest)
	var requests int32
	var signatures []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		signatures = append(signatures, r.Header.Get("X-CSM-Signature"))
		atomic.AddInt32(&requests, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := &config.Config{StatePath: t.TempDir(), Hostname: "host"}
	cfg.Alerts.MaxPerHour = 10
	cfg.Alerts.Webhook.Enabled = true
	cfg.Alerts.Webhook.Type = "phpanel"
	cfg.Alerts.Webhook.URL = srv.URL
	cfg.Alerts.Webhook.HMACSecret = "secret"
	cfg.Alerts.Webhook.PerFinding = false

	findings := []Finding{
		{Check: "a", Message: "a", Severity: Critical, Timestamp: time.Now()},
		{Check: "b", Message: "b", Severity: Critical, Timestamp: time.Now()},
	}
	if err := Dispatch(cfg, findings); err != nil {
		t.Fatal(err)
	}
	waitForWebhookRequests(t, &requests, 2)
	for _, sig := range signatures {
		if !strings.HasPrefix(sig, "sha256=") {
			t.Fatalf("missing phpanel signature in %q", sig)
		}
	}
}

func TestDispatchPhpanelWebhookBypassesOperatorRateLimit(t *testing.T) {
	t.Cleanup(closePhpanelQueuesForTest)
	var requests int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&requests, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := &config.Config{StatePath: t.TempDir(), Hostname: "host"}
	cfg.Alerts.MaxPerHour = 1
	cfg.Alerts.Webhook.Enabled = true
	cfg.Alerts.Webhook.Type = "phpanel"
	cfg.Alerts.Webhook.URL = srv.URL
	cfg.Alerts.Webhook.HMACSecret = "secret"

	for i := 0; i < 3; i++ {
		finding := Finding{
			Check:     "ssh_bruteforce",
			Message:   "failed login " + string(rune('a'+i)),
			Severity:  Warning,
			SourceIP:  "203.0.113.10",
			Timestamp: time.Now(),
		}
		if err := Dispatch(cfg, []Finding{finding}); err != nil {
			t.Fatal(err)
		}
	}
	waitForWebhookRequests(t, &requests, 3)
	if got := readRateLimitCount(t, cfg.StatePath); got != 0 {
		t.Fatalf("rate-limit count = %d, want 0", got)
	}
}

func TestDispatchPhpanelWebhookBypassesBlockedAlertSuppression(t *testing.T) {
	t.Cleanup(closePhpanelQueuesForTest)
	var requests int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&requests, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := &config.Config{StatePath: t.TempDir(), Hostname: "host"}
	cfg.Alerts.MaxPerHour = 1
	cfg.Alerts.Webhook.Enabled = true
	cfg.Alerts.Webhook.Type = "phpanel"
	cfg.Alerts.Webhook.URL = srv.URL
	cfg.Alerts.Webhook.HMACSecret = "secret"
	cfg.Suppressions.SuppressBlockedAlerts = true
	cfg.AutoResponse.Enabled = true
	cfg.AutoResponse.BlockIPs = true

	finding := Finding{
		Check:     "ip_reputation",
		Message:   "Known malicious IP detected: 203.0.113.10",
		Severity:  Warning,
		SourceIP:  "203.0.113.10",
		Timestamp: time.Now(),
	}
	if err := Dispatch(cfg, []Finding{finding}); err != nil {
		t.Fatal(err)
	}
	waitForWebhookRequests(t, &requests, 1)
}

func TestDispatchPhpanelWebhookErrorRemainsQueuedForRetry(t *testing.T) {
	t.Cleanup(closePhpanelQueuesForTest)
	var requests int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&requests, 1)
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	cfg := &config.Config{StatePath: t.TempDir(), Hostname: "host"}
	cfg.Alerts.MaxPerHour = 10
	cfg.Alerts.Webhook.Enabled = true
	cfg.Alerts.Webhook.Type = "phpanel"
	cfg.Alerts.Webhook.URL = srv.URL
	cfg.Alerts.Webhook.HMACSecret = "secret"

	if err := Dispatch(cfg, []Finding{{Check: "a", Message: "a", Severity: Critical, Timestamp: time.Now()}}); err != nil {
		t.Fatalf("durable enqueue failed: %v", err)
	}
	waitForWebhookRequests(t, &requests, 1)
	if depth := phpanelQueueDepthForTest(cfg.StatePath); depth != 1 {
		t.Fatalf("failed webhook queue depth = %d, want 1", depth)
	}
}

type blockingWebhookTransport struct {
	release <-chan struct{}
}

func (b blockingWebhookTransport) RoundTrip(*http.Request) (*http.Response, error) {
	<-b.release
	return nil, errors.New("collector unavailable")
}

func TestDispatchPhpanelWebhookDoesNotWaitForNetwork(t *testing.T) {
	release := make(chan struct{})
	restore := SetWebhookTransportForTest(blockingWebhookTransport{release: release})
	t.Cleanup(restore)
	t.Cleanup(func() {
		close(release)
		closePhpanelQueuesForTest()
	})

	cfg := &config.Config{StatePath: t.TempDir(), Hostname: "host"}
	cfg.Alerts.Webhook.Enabled = true
	cfg.Alerts.Webhook.Type = "phpanel"
	cfg.Alerts.Webhook.URL = "https://panel.invalid/findings"
	cfg.Alerts.Webhook.HMACSecret = "secret"

	started := time.Now()
	if err := Dispatch(cfg, []Finding{{Check: "a", Message: "a", Severity: Critical, Timestamp: time.Now()}}); err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(started); elapsed > 250*time.Millisecond {
		t.Fatalf("Dispatch blocked on phpanel network for %s", elapsed)
	}
	if depth := phpanelQueueDepthForTest(cfg.StatePath); depth != 1 {
		t.Fatalf("durable phpanel queue depth = %d, want 1", depth)
	}
}

func TestPhpanelQueueBatchKeepsNewestItemsAtLimit(t *testing.T) {
	t.Cleanup(closePhpanelQueuesForTest)
	cfg := &config.Config{StatePath: t.TempDir(), Hostname: "host"}
	cfg.Alerts.Webhook.URL = "https://panel.invalid/findings"
	cfg.Alerts.Webhook.HMACSecret = "secret"
	queue, err := phpanelQueueFor(cfg)
	if err != nil {
		t.Fatal(err)
	}
	items := []queuedPhpanelFinding{
		{Finding: Finding{Check: "a"}, Timestamp: time.Now()},
		{Finding: Finding{Check: "b"}, Timestamp: time.Now()},
		{Finding: Finding{Check: "c"}, Timestamp: time.Now()},
	}
	dropped, err := queue.enqueueBatch(items, 2)
	if err != nil {
		t.Fatal(err)
	}
	if dropped != 1 {
		t.Fatalf("dropped = %d, want 1", dropped)
	}
	checks := phpanelQueuedChecksForTest(t, queue)
	if !slices.Equal(checks, []string{"b", "c"}) {
		t.Fatalf("queued checks = %v, want newest batch entries [b c]", checks)
	}
}

func TestPhpanelQueueQuarantinesMalformedEntryAndContinues(t *testing.T) {
	t.Cleanup(closePhpanelQueuesForTest)
	var requests int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&requests, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := &config.Config{StatePath: t.TempDir(), Hostname: "host"}
	cfg.Alerts.Webhook.URL = srv.URL
	cfg.Alerts.Webhook.HMACSecret = "secret"
	queue, err := phpanelQueueFor(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := queue.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(phpanelQueueBucket)
		seq, err := bucket.NextSequence()
		if err != nil {
			return err
		}
		var key [8]byte
		binary.BigEndian.PutUint64(key[:], seq)
		return bucket.Put(key[:], []byte("not-json"))
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := queue.enqueueBatch([]queuedPhpanelFinding{{Finding: Finding{Check: "valid"}, Timestamp: time.Now()}}, phpanelQueueLimit); err != nil {
		t.Fatal(err)
	}

	queue.drainQueued()

	if got := atomic.LoadInt32(&requests); got != 1 {
		t.Fatalf("delivered requests = %d, want 1 after malformed entry", got)
	}
	if depth := phpanelQueueDepthForTest(cfg.StatePath); depth != 0 {
		t.Fatalf("active queue depth = %d, want 0", depth)
	}
	if quarantined := phpanelQuarantineDepthForTest(t, queue); quarantined != 1 {
		t.Fatalf("quarantined queue depth = %d, want 1", quarantined)
	}
}

func TestPhpanelQueueBoundsMalformedEntryQuarantine(t *testing.T) {
	t.Cleanup(closePhpanelQueuesForTest)
	cfg := &config.Config{StatePath: t.TempDir(), Hostname: "host"}
	cfg.Alerts.Webhook.URL = "https://panel.invalid/findings"
	cfg.Alerts.Webhook.HMACSecret = "secret"
	queue, err := phpanelQueueFor(cfg)
	if err != nil {
		t.Fatal(err)
	}
	decodeErr := errors.New("malformed record")
	const limit = 3
	for i := 1; i <= limit+1; i++ {
		var key [8]byte
		binary.BigEndian.PutUint64(key[:], uint64(i)) // #nosec G115 -- bounded positive test loop.
		payload := []byte("bad")
		if err := queue.db.Update(func(tx *bolt.Tx) error {
			return tx.Bucket(phpanelQueueBucket).Put(key[:], payload)
		}); err != nil {
			t.Fatal(err)
		}
		if err := queue.quarantineMalformedWithLimit(key[:], payload, decodeErr, limit); err != nil {
			t.Fatal(err)
		}
	}
	if depth := phpanelQuarantineDepthForTest(t, queue); depth != limit {
		t.Fatalf("quarantine depth = %d, want bounded depth %d", depth, limit)
	}
	if err := queue.db.View(func(tx *bolt.Tx) error {
		var oldest [8]byte
		binary.BigEndian.PutUint64(oldest[:], 1)
		if tx.Bucket(phpanelQuarantineBucket).Get(oldest[:]) != nil {
			t.Fatal("oldest malformed record was not evicted")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestConfigurePhpanelQueueDrainsPendingAfterRestart(t *testing.T) {
	statePath := t.TempDir()
	release := make(chan struct{})
	restore := SetWebhookTransportForTest(blockingWebhookTransport{release: release})

	cfg := &config.Config{StatePath: statePath, Hostname: "host"}
	cfg.Alerts.Webhook.Enabled = true
	cfg.Alerts.Webhook.Type = "phpanel"
	cfg.Alerts.Webhook.URL = "https://panel.invalid/findings"
	cfg.Alerts.Webhook.HMACSecret = "secret"
	if err := Dispatch(cfg, []Finding{{Check: "pending", Severity: Critical}}); err != nil {
		t.Fatal(err)
	}
	close(release)
	closePhpanelQueuesForTest()
	restore()

	var requests int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&requests, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	cfg.Alerts.Webhook.URL = srv.URL
	if err := ConfigurePhpanelQueue(cfg); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(closePhpanelQueuesForTest)
	waitForWebhookRequests(t, &requests, 1)
	waitForPhpanelQueueDepth(t, statePath, 0)
}

func TestEnqueueWithStaleConfigDoesNotUndoReloadedDeliveryConfig(t *testing.T) {
	t.Cleanup(closePhpanelQueuesForTest)
	statePath := t.TempDir()
	oldCfg := &config.Config{StatePath: statePath, Hostname: "old-host"}
	oldCfg.Alerts.Webhook.Enabled = true
	oldCfg.Alerts.Webhook.Type = "phpanel"
	oldCfg.Alerts.Webhook.URL = "https://old.invalid/findings"
	oldCfg.Alerts.Webhook.HMACSecret = "old-secret"
	if err := ConfigurePhpanelQueue(oldCfg); err != nil {
		t.Fatal(err)
	}
	newCfg := *oldCfg
	newCfg.Hostname = "new-host"
	newCfg.Alerts.Webhook.URL = "https://new.invalid/findings"
	newCfg.Alerts.Webhook.HMACSecret = "new-secret"
	if err := ConfigurePhpanelQueue(&newCfg); err != nil {
		t.Fatal(err)
	}
	if err := enqueuePhpanelFindings(oldCfg, nil); err != nil {
		t.Fatal(err)
	}

	absolute, err := filepath.Abs(statePath)
	if err != nil {
		t.Fatal(err)
	}
	phpanelQueues.Lock()
	queue := phpanelQueues.byState[absolute]
	phpanelQueues.Unlock()
	if queue == nil {
		t.Fatal("phpanel queue was not created")
	}
	queue.cfgMu.RLock()
	delivery := queue.cfg
	queue.cfgMu.RUnlock()
	if delivery.hostname != "new-host" || delivery.url != "https://new.invalid/findings" || delivery.hmacSecret != "new-secret" {
		t.Fatalf("delivery config reverted after stale enqueue: %+v", delivery)
	}
}

func phpanelQueuedChecksForTest(t *testing.T, queue *phpanelQueue) []string {
	t.Helper()
	var checks []string
	if err := queue.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(phpanelQueueBucket).ForEach(func(_, value []byte) error {
			var item queuedPhpanelFinding
			if err := json.Unmarshal(value, &item); err != nil {
				return err
			}
			checks = append(checks, item.Finding.Check)
			return nil
		})
	}); err != nil {
		t.Fatal(err)
	}
	return checks
}

func phpanelQuarantineDepthForTest(t *testing.T, queue *phpanelQueue) int {
	t.Helper()
	depth := 0
	if err := queue.db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(phpanelQuarantineBucket)
		if bucket != nil {
			depth = bucket.Stats().KeyN
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return depth
}

// newUnregisteredPhpanelQueue builds a queue with its own bbolt file but does
// not register it in phpanelQueues or start its worker, so a test can drive
// enqueueBatch/drainQueued and manipulate q.stop directly without the package
// cleanup double-closing it.
func newUnregisteredPhpanelQueue(t *testing.T, delivery phpanelDeliveryConfig) *phpanelQueue {
	t.Helper()
	db, err := bolt.Open(filepath.Join(t.TempDir(), "phpanel.db"), 0o600, &bolt.Options{Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.Update(func(tx *bolt.Tx) error {
		if _, e := tx.CreateBucketIfNotExists(phpanelQueueBucket); e != nil {
			return e
		}
		_, e := tx.CreateBucketIfNotExists(phpanelQuarantineBucket)
		return e
	}); err != nil {
		t.Fatal(err)
	}
	q := &phpanelQueue{db: db, wake: make(chan struct{}, 1), stop: make(chan struct{}), done: make(chan struct{})}
	q.cfg = delivery
	return q
}

func phpanelActiveDepth(t *testing.T, queue *phpanelQueue) int {
	t.Helper()
	depth := 0
	if err := queue.db.View(func(tx *bolt.Tx) error {
		depth = tx.Bucket(phpanelQueueBucket).Stats().KeyN
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return depth
}

func assertQueuedFindingCount(t *testing.T, q *phpanelQueue, want int) {
	t.Helper()
	if err := q.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(phpanelQueueBucket)
		if got := queuedFindingCount(b); got != want {
			t.Errorf("queuedFindingCount = %d, want %d", got, want)
		}
		if got := b.Stats().KeyN; got != want {
			t.Errorf("Stats().KeyN = %d, want %d", got, want)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

type oneSuccessWebhookTransport struct {
	requests *int32
}

func (t oneSuccessWebhookTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	status := http.StatusServiceUnavailable
	if atomic.AddInt32(t.requests, 1) == 1 {
		status = http.StatusOK
	}
	return &http.Response{
		StatusCode: status,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader("")),
		Request:    req,
	}, nil
}

func TestQueuedFindingCountTracksEveryProductionDeletePath(t *testing.T) {
	var requests int32
	restore := SetWebhookTransportForTest(oneSuccessWebhookTransport{requests: &requests})
	t.Cleanup(restore)

	q := newUnregisteredPhpanelQueue(t, phpanelDeliveryConfig{hostname: "host", url: "https://panel.invalid/findings", hmacSecret: "secret"})
	items := make([]queuedPhpanelFinding, 4)
	for i := range items {
		items[i] = queuedPhpanelFinding{Finding: Finding{Check: "c"}, Timestamp: time.Now()}
	}
	dropped, err := q.enqueueBatch(items, 3)
	if err != nil {
		t.Fatal(err)
	}
	if dropped != 1 {
		t.Fatalf("overflow dropped = %d, want 1", dropped)
	}
	assertQueuedFindingCount(t, q, 3)

	var firstKey, malformed []byte
	if err := q.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(phpanelQueueBucket)
		key, _ := b.Cursor().First()
		if key == nil {
			return errors.New("queue unexpectedly empty")
		}
		firstKey = append([]byte(nil), key...)
		malformed = []byte("not-json")
		return b.Put(firstKey, malformed)
	}); err != nil {
		t.Fatal(err)
	}
	if err := q.quarantineMalformed(firstKey, malformed, errors.New("malformed record")); err != nil {
		t.Fatal(err)
	}
	assertQueuedFindingCount(t, q, 2)

	q.drainQueued()
	if got := atomic.LoadInt32(&requests); got != 2 {
		t.Fatalf("delivery attempts = %d, want one success and one retryable failure", got)
	}
	assertQueuedFindingCount(t, q, 1)
}

func TestDrainQueuedStopsPromptlyWhenClosing(t *testing.T) {
	var delivered int32
	restore := SetWebhookTransportForTest(oneSuccessWebhookTransport{requests: &delivered})
	t.Cleanup(restore)

	q := newUnregisteredPhpanelQueue(t, phpanelDeliveryConfig{hostname: "host", url: "https://panel.invalid/findings", hmacSecret: "secret"})
	items := make([]queuedPhpanelFinding, 20)
	for i := range items {
		items[i] = queuedPhpanelFinding{Finding: Finding{Check: "c"}, Timestamp: time.Now()}
	}
	if _, err := q.enqueueBatch(items, phpanelQueueLimit); err != nil {
		t.Fatal(err)
	}

	// Shutdown requested before this drain runs. A healthy collector must not
	// keep the drain (and thus close()) busy delivering the whole backlog.
	close(q.stop)
	q.drainQueued()

	if got := atomic.LoadInt32(&delivered); got != 0 {
		t.Fatalf("drainQueued delivered %d findings after stop; must abort promptly", got)
	}
	if depth := phpanelActiveDepth(t, q); depth != 20 {
		t.Fatalf("queue depth = %d, want 20 preserved for next start", depth)
	}
}

func waitForWebhookRequests(t *testing.T, requests *int32, want int32) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for atomic.LoadInt32(requests) != want && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if got := atomic.LoadInt32(requests); got != want {
		t.Fatalf("phpanel webhook requests = %d, want %d", got, want)
	}
}

func waitForPhpanelQueueDepth(t *testing.T, statePath string, want int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for phpanelQueueDepthForTest(statePath) != want && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if got := phpanelQueueDepthForTest(statePath); got != want {
		t.Fatalf("phpanel queue depth = %d, want %d", got, want)
	}
}
