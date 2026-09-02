package threatintel

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// The upstream response could set its own cache lifetime with no ceiling: a
// misconfigured or compromised panel pinning a score of 100 for a year kept
// an address flagged (and re-blocked after every expiry) until a restart.
// The operator's cache_ttl is the ceiling.
func TestUpstreamResponseTTLIsCappedByConfig(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"ip": r.URL.Query().Get("ip"), "score": 100, "source": "upstream", "ttl_sec": 365 * 24 * 3600,
		})
	}))
	defer srv.Close()

	src := NewUpstreamSource(UpstreamConfig{URL: srv.URL, CacheTTL: time.Minute, Timeout: time.Second})
	if _, err := src.Score(context.Background(), "203.0.113.9"); err != nil {
		t.Fatal(err)
	}
	src.mu.Lock()
	entry, ok := src.cache["203.0.113.9"]
	src.mu.Unlock()
	if !ok {
		t.Fatal("score not cached")
	}
	if remaining := time.Until(entry.expires); remaining > 2*time.Minute {
		t.Fatalf("upstream ttl_sec honoured beyond the configured ceiling: %s left", remaining)
	}
}
