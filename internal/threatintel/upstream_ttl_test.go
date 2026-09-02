package threatintel

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

// The upstream response could set its own cache lifetime with no ceiling: a
// misconfigured or compromised panel pinning a score of 100 for a year kept
// an address flagged (and re-blocked after every expiry) until a restart.
// The operator's cache_ttl is the ceiling.
func TestUpstreamResponseTTLIsCappedByConfig(t *testing.T) {
	src := NewUpstreamSource(UpstreamConfig{URL: "https://example.test", CacheTTL: time.Minute, Timeout: time.Second})
	src.client = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		var body strings.Builder
		_ = json.NewEncoder(&body).Encode(map[string]interface{}{
			"ip": req.URL.Query().Get("ip"), "score": 100, "source": "upstream", "ttl_sec": 365 * 24 * 3600,
		})
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(body.String())),
			Header:     make(http.Header),
			Request:    req,
		}, nil
	})}

	if _, err := src.Score(context.Background(), "203.0.113.9"); err != nil {
		t.Fatal(err)
	}
	src.mu.Lock()
	entry, ok := src.cache["203.0.113.9"]
	src.mu.Unlock()
	if !ok {
		t.Fatal("score not cached")
	}
	if remaining := time.Until(entry.expires); remaining > time.Minute {
		t.Fatalf("upstream ttl_sec honoured beyond the configured ceiling: %s left", remaining)
	}
}
