package main

import (
	"context"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/threatintel"
)

func TestRefreshBotRangesReturnsCacheWriteFailure(t *testing.T) {
	t.Cleanup(func() { threatintel.PublishFetchedRanges(nil) })

	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader(`{"prefixes":[{"ipv4Prefix":"18.97.9.96/29"}]}`)),
			Request:    req,
		}, nil
	})}

	cachePath := filepath.Join(t.TempDir(), "missing", "botranges.json")
	n, err := refreshBotRanges(context.Background(), client, []threatintel.RangeSource{
		{Bot: "perplexitybot", URL: "https://ranges.test/perplexitybot.json"},
	}, cachePath)
	if err == nil {
		t.Fatal("refreshBotRanges should report a cache write failure")
	}
	// The refresh is atomic: when the cache cannot be persisted, nothing is
	// published and the count is zero, so the caller never reports a refresh
	// that did not durably land.
	if n != 0 {
		t.Fatalf("refreshed identities = %d, want 0 on cache write failure", n)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}
