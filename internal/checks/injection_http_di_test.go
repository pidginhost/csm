package checks

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/config"
)

// Tests for HTTP-backed Check functions, exercised with package-level
// endpoint+client vars temporarily redirected to in-process handlers.

// withTestAbuseIPDB points abuseIPDBEndpoint+Client at an in-process
// handler for the duration of the test, and returns the URL.
func withTestAbuseIPDB(t *testing.T, handler http.HandlerFunc) string {
	t.Helper()
	origURL := abuseIPDBEndpoint
	origClient := abuseIPDBClient
	abuseIPDBEndpoint = localHTTPTestURL
	abuseIPDBClient = newHandlerHTTPClient(handler)
	t.Cleanup(func() {
		abuseIPDBEndpoint = origURL
		abuseIPDBClient = origClient
	})
	return abuseIPDBEndpoint
}

// withTestHIBP swaps hibpEndpoint+Client to an in-process handler.
func withTestHIBP(t *testing.T, handler http.HandlerFunc) {
	t.Helper()
	origURL := hibpEndpoint
	origClient := hibpClient
	hibpEndpoint = localHTTPTestURL + "/"
	hibpClient = newHandlerHTTPClient(handler)
	t.Cleanup(func() {
		hibpEndpoint = origURL
		hibpClient = origClient
	})
}

// --- queryAbuseIPDB ---------------------------------------------------

func TestQueryAbuseIPDBSuccessParsesScoreAndCategory(t *testing.T) {
	withTestAbuseIPDB(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Key") != "test-key" {
			t.Error("unexpected Key header")
		}
		if r.Header.Get("Accept") != "application/json" {
			t.Errorf("missing Accept header: %s", r.Header.Get("Accept"))
		}
		if !strings.Contains(r.URL.String(), "ipAddress=203.0.113.5") {
			t.Errorf("missing ipAddress query: %s", r.URL.String())
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintln(w, `{"data":{"abuseConfidenceScore":85,"usageType":"Data Center/Web Hosting/Transit"}}`)
	})

	score, category, err := queryAbuseIPDB(abuseIPDBClient, "203.0.113.5", "test-key", nil)
	if err != nil {
		t.Fatalf("queryAbuseIPDB: %v", err)
	}
	if score != 85 {
		t.Errorf("score = %d, want 85", score)
	}
	if !strings.Contains(category, "Data Center") {
		t.Errorf("category = %q, want substring 'Data Center'", category)
	}
}

func TestQueryAbuseIPDBHTTPErrorReturnsError(t *testing.T) {
	withTestAbuseIPDB(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = fmt.Fprintln(w, `{"errors":[{"detail":"invalid api key"}]}`)
	})

	_, _, err := queryAbuseIPDB(abuseIPDBClient, "198.51.100.1", "bad-key", nil)
	if err == nil {
		t.Error("expected error on 401 response")
	}
}

func TestQueryAbuseIPDBQuotaExceededReturnsSpecificError(t *testing.T) {
	withTestAbuseIPDB(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = fmt.Fprintln(w, `{"errors":[{"detail":"Daily rate limit"}]}`)
	})

	_, _, err := queryAbuseIPDB(abuseIPDBClient, "198.51.100.1", "key", nil)
	if err == nil {
		t.Fatal("expected error on 429 response")
	}
	if !strings.Contains(err.Error(), "429") {
		t.Fatalf("expected rate-limit classification, got %v", err)
	}
}

func TestQueryAbuseIPDBMalformedJSONReturnsError(t *testing.T) {
	withTestAbuseIPDB(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintln(w, `{this is not valid json`)
	})

	_, _, err := queryAbuseIPDB(abuseIPDBClient, "198.51.100.1", "key", nil)
	if err == nil {
		t.Error("expected error on malformed JSON")
	}
}

// --- CheckIPReputation ------------------------------------------------

func TestCheckIPReputationNoRecentIPsReturnsNil(t *testing.T) {
	// No log files mocked → collectRecentIPs returns empty.
	withMockOS(t, &mockOS{})
	cfg := &config.Config{StatePath: t.TempDir()}

	findings := CheckIPReputation(context.Background(), cfg, nil)
	if findings != nil {
		t.Errorf("expected nil findings when no IPs collected, got %d", len(findings))
	}
}

func TestCheckIPReputationQuotaExhaustionStopsFurtherQueries(t *testing.T) {
	db := setupPluginStore(t)
	var calls atomic.Int32
	withTestAbuseIPDB(t, func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusTooManyRequests)
	})
	var lines []string
	for i := 1; i <= 3; i++ {
		lines = append(lines, fmt.Sprintf("Sep 10 10:00:00 host sshd[1]: Accepted publickey for alice from 198.51.100.%d port 22 ssh2", i))
	}
	withMockOS(t, mockOSWithAuthLog(t, strings.Join(lines, "\n")+"\n"))
	cfg := &config.Config{StatePath: t.TempDir()}
	cfg.Reputation.AbuseIPDBKey = t.Name()
	findings := CheckIPReputation(context.Background(), cfg, nil)
	if calls.Load() != 3 || len(findings) != 1 || findings[0].Check != "reputation_quota_exhausted" || !db.AbuseQuotaExhaustedUntil().After(time.Now()) {
		t.Fatalf("first cycle did not record all concurrent quota responses: calls=%d findings=%+v", calls.Load(), findings)
	}
	CheckIPReputation(context.Background(), cfg, nil)
	if calls.Load() != 3 {
		t.Fatalf("persisted quota backoff allowed more queries: %d", calls.Load())
	}
}

// --- checkHIBP --------------------------------------------------------

func TestCheckHIBPPasswordFoundReturnsCount(t *testing.T) {
	// SHA1("password123") = "CBFDAC6008F9CAB4083784CBD1874F76618D2A97"
	// Prefix: "CBFDA", suffix: "C6008F9CAB4083784CBD1874F76618D2A97"
	withTestHIBP(t, func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/CBFDA") {
			t.Errorf("expected request to /CBFDA, got %s", r.URL.Path)
		}
		// HIBP returns lines like "<suffix>:<count>"
		_, _ = fmt.Fprintln(w, "C6008F9CAB4083784CBD1874F76618D2A97:42")
	})

	count := checkHIBP("password123")
	if count != 42 {
		t.Errorf("checkHIBP returned %d, want 42", count)
	}
}

func TestCheckHIBPPasswordNotFoundReturnsZero(t *testing.T) {
	withTestHIBP(t, func(w http.ResponseWriter, r *http.Request) {
		// Return some other suffix that doesn't match — function returns 0.
		_, _ = fmt.Fprintln(w, "0000000000000000000000000000000000:1")
	})

	count := checkHIBP("definitely-not-in-the-list-12345")
	if count != 0 {
		t.Errorf("checkHIBP returned %d, want 0 (not found)", count)
	}
}

func TestCheckHIBPNon200StatusReturnsZero(t *testing.T) {
	withTestHIBP(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	})

	count := checkHIBP("anything")
	if count != 0 {
		t.Errorf("checkHIBP on 503 returned %d, want 0 (graceful failure)", count)
	}
}

func TestCheckHIBPNetworkErrorReturnsZero(t *testing.T) {
	origURL := hibpEndpoint
	origClient := hibpClient
	hibpEndpoint = localHTTPTestURL + "/"
	hibpClient = newFailingHTTPClient("forced HIBP transport failure")
	t.Cleanup(func() {
		hibpEndpoint = origURL
		hibpClient = origClient
	})

	count := checkHIBP("anything")
	if count != 0 {
		t.Errorf("checkHIBP on network error returned %d, want 0", count)
	}
}
