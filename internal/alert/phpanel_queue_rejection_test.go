package alert

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
)

// panelReplying answers each delivery with the status chosen for the
// finding's check and records the checks in arrival order.
func panelReplying(t *testing.T, status func(check string) int) *[]string {
	t.Helper()
	var seen []string
	restore := SetWebhookTransportForTest(phpanelHealthTransport(func(r *http.Request) (*http.Response, error) {
		var body struct {
			Finding Finding `json:"finding"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			return nil, err
		}
		seen = append(seen, body.Finding.Check)
		return &http.Response{StatusCode: status(body.Finding.Check), Header: make(http.Header), Body: io.NopCloser(strings.NewReader("")), Request: r}, nil
	}))
	t.Cleanup(restore)
	return &seen
}

func quarantinedRecordsForTest(t *testing.T, q *phpanelQueue) []quarantinedPhpanelFinding {
	t.Helper()
	var records []quarantinedPhpanelFinding
	if err := q.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(phpanelQuarantineBucket).ForEach(func(_, value []byte) error {
			var rec quarantinedPhpanelFinding
			if err := json.Unmarshal(value, &rec); err != nil {
				return err
			}
			records = append(records, rec)
			return nil
		})
	}); err != nil {
		t.Fatal(err)
	}
	return records
}

func enqueueChecks(t *testing.T, q *phpanelQueue, checks ...string) {
	t.Helper()
	items := make([]queuedPhpanelFinding, 0, len(checks))
	for _, check := range checks {
		items = append(items, queuedPhpanelFinding{Finding: Finding{Check: check}, Timestamp: time.Now()})
	}
	if _, err := q.enqueueBatch(items); err != nil {
		t.Fatal(err)
	}
}

// A record the panel refuses outright gets the same answer on every retry.
// Retrying it held every later finding behind it for good.
func TestPhpanelQueueArchivesPermanentRejectionAndDeliversNext(t *testing.T) {
	for _, code := range []int{http.StatusBadRequest, http.StatusRequestEntityTooLarge, http.StatusUnprocessableEntity} {
		t.Run(fmt.Sprint(code), func(t *testing.T) {
			seen := panelReplying(t, func(check string) int {
				if check == "refused" {
					return code
				}
				return http.StatusOK
			})
			q := newUnregisteredPhpanelQueue(t, phpanelDeliveryConfig{hostname: "host", url: "https://panel.invalid/findings", hmacSecret: rand.Text()}, phpanelQueueLimit)
			enqueueChecks(t, q, "refused", "later")

			q.drainQueued()

			if got := strings.Join(*seen, ","); got != "refused,later" {
				t.Fatalf("deliveries = %q, want the later finding sent after the refusal", got)
			}
			if depth := phpanelActiveDepth(t, q); depth != 0 {
				t.Fatalf("active depth = %d, want 0", depth)
			}
			records := quarantinedRecordsForTest(t, q)
			if len(records) != 1 || !strings.Contains(records[0].Error, fmt.Sprint(code)) {
				t.Fatalf("quarantine = %+v, want the refused record with status %d as its reason", records, code)
			}
			var archived queuedPhpanelFinding
			if err := json.Unmarshal(records[0].Payload, &archived); err != nil || archived.Finding.Check != "refused" {
				t.Fatalf("archived payload = %s (%v), want the refused finding", records[0].Payload, err)
			}
			q.retryMu.Lock()
			retryAt := q.retryAt
			q.retryMu.Unlock()
			if !retryAt.IsZero() {
				t.Fatalf("a refusal scheduled a retry at %v", retryAt)
			}
			status := phpanelHealthStatus(t, q, time.Now().Add(time.Minute))
			if status.Status != "ok" || status.Depth != 0 || status.InFlight != 0 || status.DroppedTotal != 1 {
				t.Fatalf("health after a refusal = %+v, want one lost finding and no delivery failure", status)
			}
		})
	}
}

func TestPhpanelQueueRetriesOtherFailuresInOrder(t *testing.T) {
	for _, code := range []int{http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound, http.StatusConflict, http.StatusTooManyRequests, http.StatusInternalServerError, http.StatusServiceUnavailable} {
		t.Run(fmt.Sprint(code), func(t *testing.T) {
			seen := panelReplying(t, func(string) int { return code })
			q := newUnregisteredPhpanelQueue(t, phpanelDeliveryConfig{hostname: "host", url: "https://panel.invalid/findings", hmacSecret: rand.Text()}, phpanelQueueLimit)
			enqueueChecks(t, q, "first", "second")

			q.drainQueued()

			if got := strings.Join(*seen, ","); got != "first" {
				t.Fatalf("deliveries = %q, want only the head attempted", got)
			}
			if depth := phpanelActiveDepth(t, q); depth != 2 {
				t.Fatalf("active depth = %d, want both findings kept", depth)
			}
			if n := phpanelQuarantineDepthForTest(t, q); n != 0 {
				t.Fatalf("quarantine depth = %d, want 0", n)
			}
			q.retryMu.Lock()
			retryAt := q.retryAt
			q.retryMu.Unlock()
			if !retryAt.After(time.Now()) {
				t.Fatal("a retryable failure must back off")
			}
		})
	}
}

// A panel that refuses every request (a wrong URL or node, a proxy answering
// 400) looks like a run of bad records. Past a bounded run the queue keeps
// its findings and retries, so a misconfiguration cannot empty it.
func TestPhpanelQueueKeepsFindingsAfterARunOfRefusals(t *testing.T) {
	accept := false
	seen := panelReplying(t, func(string) int {
		if accept {
			return http.StatusOK
		}
		return http.StatusBadRequest
	})
	q := newUnregisteredPhpanelQueue(t, phpanelDeliveryConfig{hostname: "host", url: "https://panel.invalid/findings", hmacSecret: rand.Text()}, phpanelQueueLimit)
	checks := make([]string, phpanelMaxRefusalRun+3)
	for i := range checks {
		checks[i] = fmt.Sprint("finding-", i)
	}
	enqueueChecks(t, q, checks...)

	q.drainQueued()

	if n := phpanelQuarantineDepthForTest(t, q); n != phpanelMaxRefusalRun {
		t.Fatalf("quarantined = %d, want the run bound %d", n, phpanelMaxRefusalRun)
	}
	if depth := phpanelActiveDepth(t, q); depth != 3 {
		t.Fatalf("active depth = %d, want the rest kept", depth)
	}
	if len(*seen) != phpanelMaxRefusalRun+1 {
		t.Fatalf("deliveries = %d, want the run plus one held attempt", len(*seen))
	}
	q.retryMu.Lock()
	retryAt := q.retryAt
	q.retryMu.Unlock()
	if !retryAt.After(time.Now()) {
		t.Fatal("a held run must back off")
	}
	status := phpanelHealthStatus(t, q, time.Now())
	if status.Status != "degraded" || status.Reason != "delivery_failed" || status.Depth != 3 {
		t.Fatalf("health with a held run = %+v, want a visible delivery failure", status)
	}

	accept = true
	q.clearRetryFailure()
	q.drainQueued()
	if depth := phpanelActiveDepth(t, q); depth != 0 {
		t.Fatalf("active depth after the panel recovers = %d, want 0", depth)
	}
	accept = false
	enqueueChecks(t, q, "refused-again")
	q.drainQueued()
	if n := phpanelQuarantineDepthForTest(t, q); n != phpanelMaxRefusalRun+1 {
		t.Fatalf("quarantined = %d, want an accepted finding to start a new run", n)
	}
}
