package wpcheck

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestScheduleRetryFiresWhenNotStopped(t *testing.T) {
	c := NewCache(t.TempDir())
	var calls atomic.Int32
	done := make(chan struct{})
	c.scheduleRetry(5*time.Millisecond, func() {
		calls.Add(1)
		close(done)
	}, nil)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatalf("retry callback never fired")
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("calls = %d, want 1", got)
	}
}

func TestScheduleRetryCancelsOnStop(t *testing.T) {
	c := NewCache(t.TempDir())
	stop := make(chan struct{})
	c.SetStopCh(stop)

	var calls atomic.Int32
	c.scheduleRetry(50*time.Millisecond, func() {
		calls.Add(1)
	}, nil)
	close(stop)
	time.Sleep(100 * time.Millisecond)
	if got := calls.Load(); got != 0 {
		t.Fatalf("calls = %d after stop, want 0 (retry must be cancelled)", got)
	}
}

func TestScheduleRetryStopMidFlightDoesNotFire(t *testing.T) {
	c := NewCache(t.TempDir())
	stop := make(chan struct{})
	c.SetStopCh(stop)

	var calls atomic.Int32
	c.scheduleRetry(200*time.Millisecond, func() {
		calls.Add(1)
	}, nil)
	time.Sleep(50 * time.Millisecond)
	close(stop)
	time.Sleep(300 * time.Millisecond)
	if got := calls.Load(); got != 0 {
		t.Fatalf("calls = %d after mid-flight stop, want 0", got)
	}
}

func TestFetchWithRetryClosedStopSkipsFetchAndClearsFlag(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		http.Error(w, "down", http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	withTestHTTPClient(t, srv)
	origT := httpClient.Transport
	httpClient.Transport = &rewriteTransport{target: srv.URL, inner: http.DefaultTransport}
	t.Cleanup(func() { httpClient.Transport = origT })

	c := NewCache(t.TempDir())
	stop := make(chan struct{})
	close(stop)
	c.SetStopCh(stop)

	key := cacheKey("6.5.2", "en_US")
	c.mu.Lock()
	c.fetching[key] = true
	c.mu.Unlock()

	c.fetchWithRetry("6.5.2", "en_US", 0)

	if got := hits.Load(); got != 0 {
		t.Fatalf("fetch hit wordpress.org path %d time(s) after stop, want 0", got)
	}
	assertNotFetching(t, c, key)
}

func TestFetchWithRetryCancelClearsInFlight(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "down", http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	withTestHTTPClient(t, srv)
	origT := httpClient.Transport
	httpClient.Transport = &rewriteTransport{target: srv.URL, inner: http.DefaultTransport}
	t.Cleanup(func() { httpClient.Transport = origT })

	c := NewCache(t.TempDir())
	stop := make(chan struct{})
	c.SetStopCh(stop)

	key := cacheKey("6.5.2", "en_US")
	c.mu.Lock()
	c.fetching[key] = true
	c.mu.Unlock()

	c.fetchWithRetry("6.5.2", "en_US", 0)
	close(stop)

	waitForNotFetching(t, c, key)
}

func TestFetchPluginWithRetryClosedStopSkipsFetchAndClearsFlag(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		http.Error(w, "down", http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	withTestHTTPClient(t, srv)
	origT := httpClient.Transport
	httpClient.Transport = &rewriteTransport{target: srv.URL, inner: http.DefaultTransport}
	t.Cleanup(func() { httpClient.Transport = origT })

	c := NewCache(t.TempDir())
	stop := make(chan struct{})
	close(stop)
	c.SetStopCh(stop)

	key := pluginKey("acme", "1.0.0")
	c.mu.Lock()
	c.fetching[key] = true
	c.mu.Unlock()

	c.fetchPluginWithRetry("acme", "1.0.0", 0)

	if got := hits.Load(); got != 0 {
		t.Fatalf("plugin fetch hit wordpress.org path %d time(s) after stop, want 0", got)
	}
	assertNotFetching(t, c, key)
}

func TestFetchPluginWithRetryCancelClearsInFlight(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "down", http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	withTestHTTPClient(t, srv)
	origT := httpClient.Transport
	httpClient.Transport = &rewriteTransport{target: srv.URL, inner: http.DefaultTransport}
	t.Cleanup(func() { httpClient.Transport = origT })

	c := NewCache(t.TempDir())
	stop := make(chan struct{})
	c.SetStopCh(stop)

	key := pluginKey("acme", "1.0.0")
	c.mu.Lock()
	c.fetching[key] = true
	c.mu.Unlock()

	c.fetchPluginWithRetry("acme", "1.0.0", 0)
	close(stop)

	waitForNotFetching(t, c, key)
}

func waitForNotFetching(t *testing.T, c *Cache, key string) {
	t.Helper()
	deadline := time.After(time.Second)
	tick := time.NewTicker(5 * time.Millisecond)
	defer tick.Stop()
	for {
		if !isFetching(c, key) {
			return
		}
		select {
		case <-deadline:
			t.Fatalf("fetching[%q] stayed true after retry cancellation", key)
		case <-tick.C:
		}
	}
}

func assertNotFetching(t *testing.T, c *Cache, key string) {
	t.Helper()
	if isFetching(c, key) {
		t.Fatalf("fetching[%q] = true after stop, want cleared", key)
	}
}

func isFetching(c *Cache, key string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.fetching[key]
}
