package checks

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
)

// Additional queryAbuseIPDB branch coverage beyond what
// injection_http_di_test.go already exercises.

func TestQueryAbuseIPDBRateLimitedReturnsSpecificError(t *testing.T) {
	url := withTestAbuseIPDB(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	})
	_ = url
	_, _, err := queryAbuseIPDB(abuseIPDBClient, "203.0.113.1", "key")
	if err == nil || !strings.Contains(err.Error(), "429") {
		t.Errorf("expected 429-specific error, got %v", err)
	}
}

func TestQueryAbuseIPDBAPIErrorInBodyReturnsError(t *testing.T) {
	withTestAbuseIPDB(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintln(w, `{"errors":[{"detail":"Invalid API key","status":401}]}`)
	})
	_, _, err := queryAbuseIPDB(abuseIPDBClient, "203.0.113.1", "bad-key")
	if err == nil || !strings.Contains(err.Error(), "Invalid API key") {
		t.Errorf("expected API error propagated, got %v", err)
	}
}

func TestQueryAbuseIPDBAppendsISPAndReportCountToCategory(t *testing.T) {
	withTestAbuseIPDB(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintln(w, `{"data":{"abuseConfidenceScore":42,"usageType":"Data Center","isp":"Evil Hosting","totalReports":17}}`)
	})
	score, cat, err := queryAbuseIPDB(abuseIPDBClient, "203.0.113.1", "k")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if score != 42 {
		t.Errorf("score = %d, want 42", score)
	}
	// Expect: "Data Center (Evil Hosting), 17 reports"
	for _, want := range []string{"Data Center", "Evil Hosting", "17 reports"} {
		if !strings.Contains(cat, want) {
			t.Errorf("category missing %q: %s", want, cat)
		}
	}
}

func TestQueryAbuseIPDBTransportErrorReturnsError(t *testing.T) {
	// Point the client at a dead TCP port (127.0.0.1:1 is never listening).
	// client.Do fails, function returns the error unchanged.
	origURL := abuseIPDBEndpoint
	origClient := abuseIPDBClient
	abuseIPDBEndpoint = "http://127.0.0.1:1"
	abuseIPDBClient = &http.Client{}
	t.Cleanup(func() {
		abuseIPDBEndpoint = origURL
		abuseIPDBClient = origClient
	})

	_, _, err := queryAbuseIPDB(abuseIPDBClient, "203.0.113.1", "k")
	if err == nil {
		t.Error("expected transport error when endpoint is unreachable")
	}
}

func TestQueryAbuseIPDBInvalidURLReturnsError(t *testing.T) {
	// Control character in the URL makes http.NewRequest fail before the
	// request is sent.
	origURL := abuseIPDBEndpoint
	abuseIPDBEndpoint = "http://\x7f bad host/"
	t.Cleanup(func() { abuseIPDBEndpoint = origURL })

	_, _, err := queryAbuseIPDB(&http.Client{}, "203.0.113.1", "k")
	if err == nil {
		t.Error("expected NewRequest error on malformed URL")
	}
}
