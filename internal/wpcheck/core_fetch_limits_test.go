package wpcheck

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func boundedCoreFetchCache(t *testing.T, status int) (*Cache, *atomic.Int32) {
	t.Helper()
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(status)
		_, _ = w.Write([]byte(`{"checksums":{"wp-includes/version.php":"11111111111111111111111111111111"}}`))
	}))
	t.Cleanup(srv.Close)
	withTestHTTPClient(t, srv)
	httpClient.Transport = &rewriteTransport{target: srv.URL, inner: http.DefaultTransport}
	c := NewCache(t.TempDir())
	stop := make(chan struct{})
	c.SetStopCh(stop)
	t.Cleanup(func() {
		close(stop)
		deadline := time.Now().Add(3 * time.Second)
		for {
			c.mu.RLock()
			pending := len(c.fetching)
			c.mu.RUnlock()
			if pending == 0 {
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf("%d checksum fetches survived shutdown", pending)
			}
			time.Sleep(time.Millisecond)
		}
	})
	return c, &hits
}

// Distinct tenant-controlled versions and locales must share a finite budget,
// including the retry timers left behind by failed HTTP requests.
func TestCoreFetchBoundsConcurrentMisses(t *testing.T) {
	c, _ := boundedCoreFetchCache(t, http.StatusServiceUnavailable)
	var callers sync.WaitGroup
	for i := range 64 {
		callers.Go(func() {
			c.Verify(Verification{Kind: KindCore, Version: fmt.Sprintf("99.0.%d", i), Locale: "en_US", Staged: true})
		})
	}
	callers.Wait()
	c.mu.RLock()
	pending := len(c.fetching)
	c.mu.RUnlock()
	if pending != 8 {
		t.Fatalf("pending fetch/retry chains = %d, want 8", pending)
	}
}

func TestCoreFetchStopsAfterRetryBudget(t *testing.T) {
	c, hits := boundedCoreFetchCache(t, http.StatusServiceUnavailable)
	key := cacheKey("99.0.1", "en_US")
	c.fetching[key] = true
	c.fetchWithRetry("99.0.1", "en_US", 4)
	if got := hits.Load(); got != 1 {
		t.Fatalf("last attempt made %d requests, want 1", got)
	}
	assertNotFetching(t, c, key)
	c.Verify(Verification{Kind: KindCore, Version: "99.0.1", Locale: "en_US", Staged: true})
	assertNotFetching(t, c, key)
}

// Fast successes must not let a stream of distinct release names bypass the
// concurrency cap and download an unbounded number of manifests at once.
func TestCoreFetchBoundsDistinctReleasesOverTime(t *testing.T) {
	c, hits := boundedCoreFetchCache(t, http.StatusOK)
	for i := range 65 {
		version := fmt.Sprintf("99.0.%d", i)
		c.Verify(Verification{Kind: KindCore, Version: version, Locale: "en_US", Staged: true})
		waitForNotFetching(t, c, cacheKey(version, "en_US"))
	}
	if got := hits.Load(); got != 64 {
		t.Fatalf("requests in one fetch window = %d, want 64", got)
	}
	if got := c.Verify(Verification{Kind: KindCore, Version: "99.0.0", Locale: "en_US", Staged: true,
		Rel: "wp-includes/version.php", Digest: "11111111111111111111111111111111"}); got != VerdictVerified {
		t.Fatalf("cached verification during throttling = %v, want verified", got)
	}
	// Expired history must release capacity for future legitimate releases.
	c.mu.Lock()
	for key := range c.coreFetchAfter {
		c.coreFetchAfter[key] = time.Now().Add(-time.Second)
	}
	c.mu.Unlock()
	c.Verify(Verification{Kind: KindCore, Version: "99.0.64", Locale: "en_US", Staged: true})
	waitForNotFetching(t, c, cacheKey("99.0.64", "en_US"))
	if got := hits.Load(); got != 65 {
		t.Fatalf("requests after expiry = %d, want 65", got)
	}
	c.mu.RLock()
	retained := len(c.coreFetchAfter)
	c.mu.RUnlock()
	if retained != 1 {
		t.Fatalf("retained fetch history = %d, want 1", retained)
	}
}
