package checks

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/queuehealth"
	"github.com/pidginhost/csm/internal/store"
)

func reputationQueueFixture(t *testing.T, count int) (*config.Config, *store.DB) {
	t.Helper()
	previous := reputationQueries
	reputationQueries = newReputationQueue()
	t.Cleanup(func() { reputationQueries = previous })
	db := setupPluginStore(t)
	var lines []string
	for i := 1; i <= count; i++ {
		lines = append(lines, fmt.Sprintf("Sep 10 10:00:00 host sshd[1]: Accepted publickey for alice from 198.51.100.%d port 22 ssh2", i))
	}
	withMockOS(t, mockOSWithAuthLog(t, strings.Join(lines, "\n")+"\n"))
	cfg := &config.Config{StatePath: t.TempDir()}
	cfg.Reputation.AbuseIPDBKey = t.Name()
	return cfg, db
}

func withReputationQueueTransport(t *testing.T, transport http.RoundTripper) {
	t.Helper()
	previous := abuseIPDBClient
	abuseIPDBClient = &http.Client{Timeout: 10 * time.Second, Transport: transport}
	t.Cleanup(func() { abuseIPDBClient = previous })
}

func reputationQueue(t *testing.T, now time.Time) queuehealth.Status {
	t.Helper()
	result := make(chan queuehealth.Status, 1)
	go func() { result <- ReputationQueueStatus(now) }()
	select {
	case q := <-result:
		return q
	case <-time.After(time.Second):
		t.Fatal("reputation health waited for HTTP, result processing or storage")
		return queuehealth.Status{}
	}
}

func waitReputationQueue(t *testing.T, depth, running int) queuehealth.Status {
	t.Helper()
	until := time.Now().Add(3 * time.Second)
	for {
		q := reputationQueue(t, time.Now())
		if q.Depth == depth && q.InFlight == running {
			return q
		}
		if !time.Now().Before(until) {
			t.Fatalf("queue never reached depth=%d running=%d: %+v", depth, running, q)
		}
		time.Sleep(time.Millisecond)
	}
}

func reputationQueueResponse(r *http.Request, status int, body io.ReadCloser) *http.Response {
	return &http.Response{StatusCode: status, Header: make(http.Header), Body: body, Request: r}
}

func assertReputationQueueFindings(t *testing.T, findings []alert.Finding, count int) {
	t.Helper()
	if len(findings) != count {
		t.Fatalf("findings=%+v, want %d reputation findings", findings, count)
	}
	seen := make(map[string]bool)
	for _, f := range findings {
		if f.Check != "ip_reputation" || f.Severity != alert.Critical || f.SourceIP == "" || seen[f.SourceIP] {
			t.Fatalf("reputation finding changed or duplicated: %+v", f)
		}
		seen[f.SourceIP] = true
	}
	for i := 1; i <= count; i++ {
		if !seen[fmt.Sprintf("198.51.100.%d", i)] {
			t.Fatalf("missing finding for fixture IP %d", i)
		}
	}
}

func TestReputationQueueQueriesAndBufferedResults(t *testing.T) {
	cfg, db := reputationQueueFixture(t, 5)
	entered, peers, slow := make(chan struct{}, 5), make(chan struct{}), make(chan struct{})
	finishPeers, finishSlow := sync.OnceFunc(func() { close(peers) }), sync.OnceFunc(func() { close(slow) })
	defer finishPeers()
	defer finishSlow()
	withReputationQueueTransport(t, roundTripFunc(func(r *http.Request) (*http.Response, error) {
		entered <- struct{}{}
		if r.URL.Query().Get("ipAddress") == "198.51.100.1" {
			<-slow
		} else {
			<-peers
		}
		return reputationQueueResponse(r, 200, io.NopCloser(strings.NewReader(`{"data":{"abuseConfidenceScore":80}}`))), nil
	}))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan []alert.Finding, 1)
	go func() { done <- CheckIPReputation(ctx, cfg, nil) }()
	joined := false
	defer func() {
		finishPeers()
		finishSlow()
		if !joined {
			select {
			case <-done:
			case <-time.After(3 * time.Second):
				t.Error("check did not finish during cleanup")
			}
		}
	}()
	for range 5 {
		select {
		case <-entered:
		case <-time.After(3 * time.Second):
			t.Fatal("five HTTP queries did not start")
		}
	}
	active := reputationQueue(t, time.Now())
	if active.Depth != 0 || active.InFlight != 5 || active.DroppedTotal != 0 || active.Status != "ok" || !active.CapacityUnavailable {
		t.Fatalf("active query pool: %+v", active)
	}
	if q := reputationQueue(t, time.Now().Add(11*time.Second)); q.Reason != "processing_lag" {
		t.Fatalf("HTTP timeout budget not used: %+v", q)
	}
	finishPeers()
	buffered := waitReputationQueue(t, 4, 1)
	if buffered.DroppedTotal != 0 {
		t.Fatalf("buffered valid replies counted as lost: %+v", buffered)
	}
	if q := reputationQueue(t, time.Now().Add(61*time.Second)); q.Reason != "backlog_lag" {
		t.Fatalf("buffered result waiting age hidden: %+v", q)
	}
	cancel()
	if q := reputationQueue(t, time.Now()); q.Depth != 4 || q.InFlight != 1 || q.DroppedTotal != 0 {
		t.Fatalf("parent cancellation lost actual queries/results: %+v", q)
	}
	finishSlow()
	select {
	case findings := <-done:
		joined = true
		assertReputationQueueFindings(t, findings, 5)
	case <-time.After(3 * time.Second):
		t.Fatal("queries did not drain")
	}
	if q := reputationQueue(t, time.Now()); q.Depth != 0 || q.InFlight != 0 || q.DroppedTotal != 0 {
		t.Fatalf("completed queries not released: %+v", q)
	}
	entries := db.AllReputation()
	if len(entries) != 5 || db.AbuseQueryCount(time.Now().UTC().Format("2006-01-02")) != 5 {
		t.Fatal("successful query records or quota count changed")
	}
	for _, entry := range entries {
		if entry.Score != 80 {
			t.Fatalf("wrong cached score: %+v", entry)
		}
	}
}

type reputationQueueCloseBody struct {
	io.Reader
	close func()
}

func (b reputationQueueCloseBody) Close() error { b.close(); return nil }

func TestReputationQueueFailureVisibleDuringBodyCleanup(t *testing.T) {
	cfg, db := reputationQueueFixture(t, 3)
	entered, release := make(chan struct{}, 3), make(chan struct{})
	finish := sync.OnceFunc(func() { close(release) })
	defer finish()
	withReputationQueueTransport(t, roundTripFunc(func(r *http.Request) (*http.Response, error) {
		body := reputationQueueCloseBody{Reader: strings.NewReader(""), close: func() { entered <- struct{}{}; <-release }}
		return reputationQueueResponse(r, 500, body), nil
	}))
	done := make(chan []alert.Finding, 1)
	go func() { done <- CheckIPReputation(context.Background(), cfg, nil) }()
	joined := false
	defer func() {
		finish()
		if !joined {
			select {
			case <-done:
			case <-time.After(3 * time.Second):
				t.Error("cleanup did not finish")
			}
		}
	}()
	for range 3 {
		select {
		case <-entered:
		case <-time.After(3 * time.Second):
			t.Fatal("response cleanup not reached")
		}
	}
	if q := reputationQueue(t, time.Now().Add(11*time.Second)); q.Depth != 0 || q.InFlight != 3 || q.DroppedTotal != 3 || q.Reason != "dropped_work" {
		t.Fatalf("known failures hidden by cleanup or cleanup borrowed HTTP deadline: %+v", q)
	}
	if q := reputationQueue(t, time.Now().Add(61*time.Second)); q.Reason != "processing_lag" {
		t.Fatalf("response cleanup stall hidden: %+v", q)
	}
	finish()
	select {
	case findings := <-done:
		joined = true
		if len(findings) != 0 {
			t.Fatalf("HTTP failure created reputation findings: %+v", findings)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("failed queries did not drain")
	}
	if q := reputationQueue(t, time.Now()); q.Depth != 0 || q.InFlight != 0 || q.DroppedTotal != 3 {
		t.Fatalf("failed queries not settled exactly once: %+v", q)
	}
	entries := db.AllReputation()
	if len(entries) != 3 {
		t.Fatalf("error cache lost: %+v", entries)
	}
	for _, e := range entries {
		if e.Score != -1 || !strings.Contains(e.Category, "HTTP 500") {
			t.Fatalf("error cache semantics changed: %+v", e)
		}
	}
	if q := reputationQueue(t, time.Now().Add(time.Minute)); q.Status != "ok" || q.RecentDrops != 0 || q.DroppedTotal != 3 {
		t.Fatalf("recovery discarded loss evidence: %+v", q)
	}
}

func TestReputationQueueCacheFailureKeepsFindings(t *testing.T) {
	cfg, db := reputationQueueFixture(t, 3)
	closeDB := sync.OnceFunc(func() {
		if err := db.Close(); err != nil {
			t.Error(err)
		}
	})
	withReputationQueueTransport(t, roundTripFunc(func(r *http.Request) (*http.Response, error) {
		closeDB()
		return reputationQueueResponse(r, 200, io.NopCloser(strings.NewReader(`{"data":{"abuseConfidenceScore":80}}`))), nil
	}))
	findings := CheckIPReputation(context.Background(), cfg, nil)
	assertReputationQueueFindings(t, findings, 3)
	if q := reputationQueue(t, time.Now()); q.Depth != 0 || q.InFlight != 0 || q.DroppedTotal != 3 || q.Reason != "dropped_work" {
		t.Fatalf("failed cache writes not counted per result: %+v", q)
	}
	reopened, err := store.Open(filepath.Dir(db.Path()))
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := reopened.Close(); err != nil {
			t.Error(err)
		}
	}()
	if len(reopened.AllReputation()) != 0 || reopened.AbuseQueryCount(time.Now().UTC().Format("2006-01-02")) != 3 {
		t.Fatal("failed cache commit was treated as stored, or reserved quota lost")
	}
}

func TestReputationQueueQuotaResponseAndRefusalAreExpected(t *testing.T) {
	cfg, db := reputationQueueFixture(t, 3)
	var calls atomic.Int32
	withReputationQueueTransport(t, roundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls.Add(1)
		status := 429
		if r.URL.Query().Get("ipAddress") == "198.51.100.1" {
			status = 402
		}
		return reputationQueueResponse(r, status, io.NopCloser(strings.NewReader(""))), nil
	}))
	findings := CheckIPReputation(context.Background(), cfg, nil)
	if calls.Load() != 3 || len(findings) != 1 || findings[0].Check != "reputation_quota_exhausted" || len(db.AllReputation()) != 0 || !db.AbuseQuotaExhaustedUntil().After(time.Now()) {
		t.Fatalf("quota classification or persistence changed: calls=%d findings=%+v", calls.Load(), findings)
	}
	if q := reputationQueue(t, time.Now()); q.Depth != 0 || q.InFlight != 0 || q.DroppedTotal != 0 {
		t.Fatalf("expected quota response counted as queue loss: %+v", q)
	}
	findings = CheckIPReputation(context.Background(), cfg, nil)
	if calls.Load() != 3 || len(findings) != 1 || findings[0].Check != "reputation_quota_exhausted" {
		t.Fatal("quota refusal dispatched new HTTP work or lost its health finding")
	}
	if q := reputationQueue(t, time.Now()); q.Depth != 0 || q.InFlight != 0 || q.DroppedTotal != 0 {
		t.Fatalf("expected local refusal counted as queue loss: %+v", q)
	}
}

func TestReputationQueueBufferedResultsRespectActiveConsumerBudget(t *testing.T) {
	cfg, db := reputationQueueFixture(t, 3)
	cfg.Reputation.Upstream.Enabled = true
	cfg.Reputation.Upstream.URL = "https://example.test"
	cfg.Reputation.Upstream.TimeoutSec = 60
	cfg.Reputation.Rspamd.Enabled = true
	cfg.Reputation.Rspamd.URL = "https://rspamd.example.test"
	entered, release := make(chan struct{}), make(chan struct{})
	finish := sync.OnceFunc(func() { close(release) })
	defer finish()
	var once sync.Once
	withDefaultHTTPTransport(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Host == "rspamd.example.test" {
			_, _ = fmt.Fprint(w, `[]`)
			return
		}
		once.Do(func() { close(entered) })
		<-release
		_, _ = fmt.Fprintf(w, `{"ip":%q,"score":80,"source":"panel"}`, r.URL.Query().Get("ip"))
	}))
	withReputationQueueTransport(t, roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return reputationQueueResponse(r, 200, io.NopCloser(strings.NewReader(`{"data":{"abuseConfidenceScore":80}}`))), nil
	}))
	done := make(chan []alert.Finding, 1)
	go func() { done <- CheckIPReputation(context.Background(), cfg, nil) }()
	joined := false
	defer func() {
		finish()
		if !joined {
			select {
			case <-done:
			case <-time.After(3 * time.Second):
				t.Error("result processing did not finish")
			}
		}
	}()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("supplemental result processing not reached")
	}
	if q := reputationQueue(t, time.Now().Add(61*time.Second)); q.Depth != 2 || q.InFlight != 1 || q.DroppedTotal != 0 || q.Status != "ok" {
		t.Fatalf("busy result consumer caused false backlog: %+v", q)
	}
	if q := reputationQueue(t, time.Now().Add(66*time.Second)); q.Reason != "processing_lag" {
		t.Fatalf("supplemental consumer ignored its own bounded budget: %+v", q)
	}
	finish()
	select {
	case findings := <-done:
		joined = true
		assertReputationQueueFindings(t, findings, 3)
	case <-time.After(3 * time.Second):
		t.Fatal("results did not drain")
	}
	if q := reputationQueue(t, time.Now()); q.Depth != 0 || q.InFlight != 0 || q.DroppedTotal != 0 {
		t.Fatalf("result delivery did not settle: %+v", q)
	}
	if len(db.AllReputation()) != 3 {
		t.Fatal("supplemental evaluation lost cache commits")
	}
}

func TestReputationQueueDistinctFailuresCountOnce(t *testing.T) {
	cfg, db := reputationQueueFixture(t, 4)
	withReputationQueueTransport(t, roundTripFunc(func(r *http.Request) (*http.Response, error) {
		switch r.URL.Query().Get("ipAddress") {
		case "198.51.100.1":
			return nil, context.DeadlineExceeded
		case "198.51.100.2":
			return nil, errors.New("fixture transport failure")
		case "198.51.100.3":
			return reputationQueueResponse(r, 200, io.NopCloser(strings.NewReader("invalid JSON"))), nil
		default:
			return reputationQueueResponse(r, 200, io.NopCloser(strings.NewReader(`{"errors":[{"detail":"fixture API failure"}]}`))), nil
		}
	}))
	if findings := CheckIPReputation(context.Background(), cfg, nil); len(findings) != 0 {
		t.Fatalf("failed requests produced findings: %+v", findings)
	}
	entries := db.AllReputation()
	if len(entries) != 4 {
		t.Fatalf("failed request cache count=%d, want 4", len(entries))
	}
	for i, reason := range []string{"context deadline exceeded", "fixture transport failure", "invalid character", "fixture API failure"} {
		e, ok := entries[fmt.Sprintf("198.51.100.%d", i+1)]
		if !ok || e.Score != -1 || !strings.Contains(e.Category, reason) {
			t.Fatalf("failure %d was not exercised and cached: %+v", i+1, e)
		}
	}
	if q := reputationQueue(t, time.Now()); q.Depth != 0 || q.InFlight != 0 || q.DroppedTotal != 4 || q.RecentDrops != 4 {
		t.Fatalf("distinct failures counted incorrectly: %+v", q)
	}
}

func TestReputationQueueQuotaBackoffFailureCountsLostResults(t *testing.T) {
	cfg, db := reputationQueueFixture(t, 3)
	closeDB := sync.OnceFunc(func() {
		if err := db.Close(); err != nil {
			t.Error(err)
		}
	})
	withReputationQueueTransport(t, roundTripFunc(func(r *http.Request) (*http.Response, error) {
		closeDB()
		return reputationQueueResponse(r, 429, io.NopCloser(strings.NewReader(""))), nil
	}))
	findings := CheckIPReputation(context.Background(), cfg, nil)
	if len(findings) != 1 || findings[0].Check != "reputation_quota_exhausted" {
		t.Fatalf("quota warning lost after failed backoff write: %+v", findings)
	}
	if q := reputationQueue(t, time.Now()); q.Depth != 0 || q.InFlight != 0 || q.DroppedTotal != 3 || q.Reason != "dropped_work" {
		t.Fatalf("failed quota backoff not counted per result: %+v", q)
	}
}

func TestReputationQueueAbnormalWorkersReleaseLostResults(t *testing.T) {
	cfg, db := reputationQueueFixture(t, 5)
	var calls atomic.Int32
	withReputationQueueTransport(t, roundTripFunc(func(*http.Request) (*http.Response, error) {
		calls.Add(1)
		runtime.Goexit()
		return nil, nil
	}))
	done := make(chan []alert.Finding, 1)
	go func() { done <- CheckIPReputation(context.Background(), cfg, nil) }()
	select {
	case findings := <-done:
		if len(findings) != 0 {
			t.Fatalf("abandoned requests created findings: %+v", findings)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("abnormal workers stranded the check")
	}
	if q := reputationQueue(t, time.Now()); q.Depth != 0 || q.InFlight != 0 || q.DroppedTotal != 5 || calls.Load() != 5 {
		t.Fatalf("abnormal requests not settled once: calls=%d queue=%+v", calls.Load(), q)
	}
	if len(db.AllReputation()) != 0 {
		t.Fatal("missing responses created cache entries")
	}
}

func TestReputationQueueFlatFileFailuresKeepFindings(t *testing.T) {
	for _, failure := range []string{"write", "rename"} {
		t.Run(failure, func(t *testing.T) {
			cfg, _ := reputationQueueFixture(t, 3)
			previous := store.Global()
			store.SetGlobal(nil)
			defer store.SetGlobal(previous)
			if failure == "write" {
				cfg.StatePath = filepath.Join(t.TempDir(), "missing")
			} else {
				if err := os.Mkdir(filepath.Join(cfg.StatePath, reputationCacheFile), 0700); err != nil {
					t.Fatal(err)
				}
			}
			withReputationQueueTransport(t, roundTripFunc(func(r *http.Request) (*http.Response, error) {
				return reputationQueueResponse(r, 200, io.NopCloser(strings.NewReader(`{"data":{"abuseConfidenceScore":80}}`))), nil
			}))
			findings := CheckIPReputation(context.Background(), cfg, nil)
			assertReputationQueueFindings(t, findings, 3)
			if q := reputationQueue(t, time.Now()); q.Depth != 0 || q.InFlight != 0 || q.DroppedTotal != 3 {
				t.Fatalf("failed flat-file %s not counted: %+v", failure, q)
			}
			if entries := loadReputationCache(cfg.StatePath).Entries; len(entries) != 0 {
				t.Fatalf("failed flat-file %s stored results: %+v", failure, entries)
			}
		})
	}
}
