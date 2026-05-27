package threatintel

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestUpstreamSource_QueriesAndParses(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/lookup" {
			t.Fatalf("expected /lookup request, got %s", r.URL.Path)
		}
		ip := r.URL.Query().Get("ip")
		if ip != "1.2.3.4" {
			t.Errorf("expected ip=1.2.3.4, got %q", ip)
		}
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Errorf("expected Bearer test-token, got %q", r.Header.Get("Authorization"))
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"ip": ip, "score": 75, "source": "upstream",
		})
	}))
	defer srv.Close()

	src := NewUpstreamSource(UpstreamConfig{
		URL:      srv.URL,
		Token:    "test-token",
		CacheTTL: time.Minute,
		Timeout:  time.Second,
	})
	got, err := src.Score(context.Background(), "1.2.3.4")
	if err != nil {
		t.Fatal(err)
	}
	if got != 75 {
		t.Fatalf("expected score=75, got %d", got)
	}
}

func TestUpstreamSource_JoinsLookupPathWithTrailingSlash(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"ip": r.URL.Query().Get("ip"), "score": 25,
		})
	}))
	defer srv.Close()

	src := NewUpstreamSource(UpstreamConfig{
		URL:      srv.URL + "/api/csm/ti/",
		CacheTTL: time.Minute,
		Timeout:  time.Second,
	})
	if _, err := src.Score(context.Background(), "1.2.3.4"); err != nil {
		t.Fatal(err)
	}
	if gotPath != "/api/csm/ti/lookup" {
		t.Fatalf("expected clean lookup path, got %q", gotPath)
	}
}

func TestUpstreamSource_CacheHitDoesNotHitNetwork(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"ip": r.URL.Query().Get("ip"), "score": 50,
		})
	}))
	defer srv.Close()

	src := NewUpstreamSource(UpstreamConfig{URL: srv.URL, CacheTTL: time.Minute, Timeout: time.Second})
	for i := 0; i < 5; i++ {
		_, _ = src.Score(context.Background(), "1.2.3.4")
	}
	if atomic.LoadInt32(&calls) != 1 {
		t.Fatalf("expected 1 upstream call (4 cache hits), got %d", calls)
	}
}

func TestUpstreamSource_UsesResponseTTL(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		score := 20 + int(atomic.AddInt32(&calls, 1))
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"ip": r.URL.Query().Get("ip"), "score": score, "ttl_sec": 1,
		})
	}))
	defer srv.Close()

	src := NewUpstreamSource(UpstreamConfig{URL: srv.URL, CacheTTL: time.Hour, Timeout: time.Second})
	first, err := src.Score(context.Background(), "1.2.3.4")
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(1100 * time.Millisecond)
	second, err := src.Score(context.Background(), "1.2.3.4")
	if err != nil {
		t.Fatal(err)
	}
	if first == second || atomic.LoadInt32(&calls) != 2 {
		t.Fatalf("expected ttl_sec to expire cache, first=%d second=%d calls=%d", first, second, calls)
	}
}

func TestUpstreamSource_TimeoutReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		fmt.Fprintln(w, "{}")
	}))
	defer srv.Close()

	src := NewUpstreamSource(UpstreamConfig{URL: srv.URL, CacheTTL: time.Minute, Timeout: 50 * time.Millisecond})
	if _, err := src.Score(context.Background(), "1.2.3.4"); err == nil {
		t.Fatal("expected timeout error")
	}
}

func TestUpstreamSource_5xxReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	src := NewUpstreamSource(UpstreamConfig{URL: srv.URL, CacheTTL: time.Minute, Timeout: time.Second})
	if _, err := src.Score(context.Background(), "1.2.3.4"); err == nil {
		t.Fatal("expected error on 5xx")
	}
}

func TestUpstreamSource_RejectsIPMismatch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"ip": "5.6.7.8", "score": 75,
		})
	}))
	defer srv.Close()

	src := NewUpstreamSource(UpstreamConfig{URL: srv.URL, CacheTTL: time.Minute, Timeout: time.Second})
	if _, err := src.Score(context.Background(), "1.2.3.4"); err == nil {
		t.Fatal("expected error on mismatched response IP")
	}
}

func TestUpstreamSource_RejectsOutOfRangeScore(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"ip": r.URL.Query().Get("ip"), "score": 150,
		})
	}))
	defer srv.Close()

	src := NewUpstreamSource(UpstreamConfig{URL: srv.URL, CacheTTL: time.Minute, Timeout: time.Second})
	if _, err := src.Score(context.Background(), "1.2.3.4"); err == nil {
		t.Fatal("expected error on out-of-range score")
	}
}

func TestUpstreamSource_ResolvesTokenFromEnv(t *testing.T) {
	const envVar = "TEST_UPSTREAM_TOKEN"
	t.Setenv(envVar, "secret-from-env")

	var capturedAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedAuth = r.Header.Get("Authorization")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"ip": r.URL.Query().Get("ip"), "score": 10,
		})
	}))
	defer srv.Close()

	// Static token left empty; env var should win at Score time.
	src := NewUpstreamSource(UpstreamConfig{URL: srv.URL, TokenEnv: envVar, CacheTTL: time.Minute, Timeout: time.Second})
	if _, err := src.Score(context.Background(), "1.2.3.4"); err != nil {
		t.Fatal(err)
	}
	if capturedAuth != "Bearer secret-from-env" {
		t.Fatalf("expected env-resolved bearer, got %q", capturedAuth)
	}
}

// TestUpstreamSource_CacheEvictsExpiredEntries: cache must not grow
// unbounded under sustained traffic with unique IPs. Once the cap is
// reached, the oldest (or expired) entries are evicted instead of the
// map silently growing forever.
func TestUpstreamSource_CacheEvictsExpiredEntries(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"ip": r.URL.Query().Get("ip"), "score": 50, "ttl_sec": 1,
		})
	}))
	defer srv.Close()

	src := NewUpstreamSource(UpstreamConfig{URL: srv.URL, CacheTTL: time.Millisecond, Timeout: time.Second})
	src.maxCacheEntries = 16
	for i := 0; i < 100; i++ {
		ip := fmt.Sprintf("198.51.100.%d", i%200)
		if _, err := src.Score(context.Background(), ip); err != nil {
			t.Fatalf("Score(%s): %v", ip, err)
		}
	}
	if got := src.cacheLen(); got > 16 {
		t.Fatalf("cache grew to %d entries, want <= 16", got)
	}
}

// TestUpstreamSource_CircuitBreakerSkipsCallsAfterFailures: sustained
// upstream failures must trip a breaker so Score returns immediately
// for the cooldown window instead of repeatedly stalling on a dead
// upstream.
func TestUpstreamSource_CircuitBreakerSkipsCallsAfterFailures(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	src := NewUpstreamSource(UpstreamConfig{URL: srv.URL, CacheTTL: time.Minute, Timeout: 100 * time.Millisecond})
	src.breakerTrip = 3
	src.breakerCooldown = time.Hour

	for i := 0; i < 3; i++ {
		ip := fmt.Sprintf("198.51.100.%d", i)
		if _, err := src.Score(context.Background(), ip); err == nil {
			t.Fatalf("expected failure for %s", ip)
		}
	}
	tripHits := atomic.LoadInt32(&hits)
	for i := 0; i < 10; i++ {
		ip := fmt.Sprintf("198.51.100.%d", 100+i)
		if _, err := src.Score(context.Background(), ip); err == nil {
			t.Fatalf("expected breaker error for %s", ip)
		}
	}
	if atomic.LoadInt32(&hits) != tripHits {
		t.Fatalf("breaker did not trip: pre=%d post=%d (each Score should short-circuit)", tripHits, atomic.LoadInt32(&hits))
	}
}

func TestUpstreamSource_CircuitBreakerAllowsSingleCooldownProbe(t *testing.T) {
	var hits int32
	var phase int32
	releaseProbe := make(chan struct{})
	probeEntered := make(chan struct{}, 16)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		if atomic.LoadInt32(&phase) == 0 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		select {
		case probeEntered <- struct{}{}:
		default:
		}
		<-releaseProbe
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"ip": r.URL.Query().Get("ip"), "score": 50,
		})
	}))
	defer srv.Close()

	src := NewUpstreamSource(UpstreamConfig{URL: srv.URL, CacheTTL: time.Minute, Timeout: time.Second})
	src.breakerTrip = 1
	src.breakerCooldown = 10 * time.Millisecond

	if _, err := src.Score(context.Background(), "198.51.100.1"); err == nil {
		t.Fatal("expected first upstream failure to trip breaker")
	}
	atomic.StoreInt32(&phase, 1)
	time.Sleep(2 * src.breakerCooldown)

	errs := make(chan error, 8)
	for i := 0; i < cap(errs); i++ {
		go func(i int) {
			_, err := src.Score(context.Background(), fmt.Sprintf("198.51.100.%d", 20+i))
			errs <- err
		}(i)
	}

	select {
	case <-probeEntered:
	case <-time.After(time.Second):
		close(releaseProbe)
		t.Fatal("expected one cooldown probe to reach upstream")
	}
	blocked := 0
	for blocked < cap(errs)-1 {
		select {
		case err := <-errs:
			if err == nil {
				close(releaseProbe)
				t.Fatal("unexpected extra probe completed before the first probe was released")
			}
			if err.Error() != "upstream breaker probe already running" {
				close(releaseProbe)
				t.Fatalf("unexpected breaker error: %v", err)
			}
			blocked++
		case <-time.After(time.Second):
			close(releaseProbe)
			t.Fatalf("only %d callers were blocked during half-open probe, want %d", blocked, cap(errs)-1)
		}
	}
	time.Sleep(50 * time.Millisecond)
	if got := atomic.LoadInt32(&hits); got != 2 {
		close(releaseProbe)
		t.Fatalf("cooldown allowed %d upstream calls, want exactly 1 probe after initial failure", got-1)
	}
	close(releaseProbe)

	if err := <-errs; err != nil {
		t.Fatalf("cooldown probe returned error: %v", err)
	}
}
