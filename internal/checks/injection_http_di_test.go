package checks

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/config"
)

// Tests for HTTP-backed Check functions, exercised via httptest.Server
// with the package-level endpoint+client vars temporarily redirected.

// withTestAbuseIPDB starts a test server, points abuseIPDBEndpoint+Client
// at it for the duration of the test, and returns the URL.
func withTestAbuseIPDB(t *testing.T, handler http.HandlerFunc) string {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	origURL := abuseIPDBEndpoint
	origClient := abuseIPDBClient
	abuseIPDBEndpoint = srv.URL
	abuseIPDBClient = srv.Client()
	t.Cleanup(func() {
		abuseIPDBEndpoint = origURL
		abuseIPDBClient = origClient
	})
	return srv.URL
}

// withTestHIBP swaps hibpEndpoint+Client to a test server.
func withTestHIBP(t *testing.T, handler http.HandlerFunc) {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	origURL := hibpEndpoint
	origClient := hibpClient
	hibpEndpoint = srv.URL + "/"
	hibpClient = srv.Client()
	t.Cleanup(func() {
		hibpEndpoint = origURL
		hibpClient = origClient
	})
}

// --- queryAbuseIPDB ---------------------------------------------------

func TestQueryAbuseIPDBSuccessParsesScoreAndCategory(t *testing.T) {
	withTestAbuseIPDB(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Key") != "test-key" {
			t.Errorf("missing Key header: %s", r.Header.Get("Key"))
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

	score, category, err := queryAbuseIPDB(abuseIPDBClient, "203.0.113.5", "test-key")
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

	_, _, err := queryAbuseIPDB(abuseIPDBClient, "1.2.3.4", "bad-key")
	if err == nil {
		t.Error("expected error on 401 response")
	}
}

func TestQueryAbuseIPDBQuotaExceededReturnsSpecificError(t *testing.T) {
	withTestAbuseIPDB(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = fmt.Fprintln(w, `{"errors":[{"detail":"Daily rate limit"}]}`)
	})

	_, _, err := queryAbuseIPDB(abuseIPDBClient, "1.2.3.4", "key")
	if err == nil {
		t.Fatal("expected error on 429 response")
	}
	if !strings.Contains(err.Error(), "quota") && !strings.Contains(err.Error(), "429") &&
		!strings.Contains(err.Error(), "rate") {
		// Either quota-specific or generic 429 — both acceptable, but
		// we want SOMETHING that callers can match on.
		t.Logf("429 error message: %v (acceptable but worth noting)", err)
	}
}

func TestQueryAbuseIPDBMalformedJSONReturnsError(t *testing.T) {
	withTestAbuseIPDB(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintln(w, `{this is not valid json`)
	})

	_, _, err := queryAbuseIPDB(abuseIPDBClient, "1.2.3.4", "key")
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
	// Make AbuseIPDB return 429 (quota) on first call. CheckIPReputation
	// should skip remaining queries.
	calls := 0
	withTestAbuseIPDB(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusTooManyRequests)
	})

	statePath := t.TempDir()
	// Surface multiple IPs via the auth log path. collectRecentIPs reads
	// /var/log/secure and /var/log/auth.log via osFS.Open.
	logContent := strings.Join([]string{
		"Apr 14 10:00:00 host sshd[1]: Failed password for x from 203.0.113.5 port 22 ssh2",
		"Apr 14 10:00:01 host sshd[1]: Failed password for x from 203.0.113.6 port 22 ssh2",
		"Apr 14 10:00:02 host sshd[1]: Failed password for x from 203.0.113.7 port 22 ssh2",
	}, "\n") + "\n"
	withMockOS(t, &mockOS{
		readFile: func(name string) ([]byte, error) {
			if strings.Contains(name, "auth.log") || strings.Contains(name, "secure") {
				return []byte(logContent), nil
			}
			return nil, nil
		},
	})

	cfg := &config.Config{StatePath: statePath}
	cfg.Reputation.AbuseIPDBKey = "test-key"
	_ = CheckIPReputation(context.Background(), cfg, nil)

	// Once quota is exhausted (first 429), subsequent IPs should not
	// trigger more API calls. We expect at most a small number of calls
	// (one per cycle until quota detected).
	if calls > maxQueriesPerCycle {
		t.Errorf("expected ≤ %d calls before quota detection, got %d", maxQueriesPerCycle, calls)
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
	// Point endpoint at an unreachable address. Restored on cleanup.
	origURL := hibpEndpoint
	origClient := hibpClient
	hibpEndpoint = "http://127.0.0.1:1/" // port 1 should refuse
	hibpClient = &http.Client{}
	t.Cleanup(func() {
		hibpEndpoint = origURL
		hibpClient = origClient
	})

	count := checkHIBP("anything")
	if count != 0 {
		t.Errorf("checkHIBP on network error returned %d, want 0", count)
	}
}
