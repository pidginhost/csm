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
