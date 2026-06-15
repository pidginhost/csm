package checks

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

// mockOSWithAuthLog returns a mockOS that serves the given content as the
// platform auth log. ReadFile and other operations fall through to the real
// filesystem so reputation_cache and other genuine file lookups succeed.
func mockOSWithAuthLog(t *testing.T, content string) *mockOS {
	t.Helper()
	tmp := filepath.Join(t.TempDir(), "auth.log")
	if err := os.WriteFile(tmp, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	return &mockOS{
		open: func(name string) (*os.File, error) {
			if name == "/var/log/secure" || name == "/var/log/auth.log" {
				return os.Open(tmp)
			}
			return nil, os.ErrNotExist
		},
		stat: func(name string) (os.FileInfo, error) {
			if name == "/var/log/secure" || name == "/var/log/auth.log" {
				return os.Stat(tmp)
			}
			return nil, os.ErrNotExist
		},
		readFile: os.ReadFile,
	}
}

// --- CheckIPReputation: cache hit with high score emits Critical ----

func TestCheckIPReputationCachedHighScoreEmitsCritical(t *testing.T) {
	statePath := t.TempDir()
	// Pre-populate cache with a malicious IP fresh enough to be used.
	cache := &reputationCache{Entries: map[string]*reputationEntry{
		"203.0.113.99": {
			Score:     90,
			Category:  "Data Center",
			CheckedAt: time.Now(),
		},
	}}
	saveReputationCache(statePath, cache)

	// Surface the IP via the platform auth log.
	logContent := "Apr 14 10:00:00 host sshd[1]: Accepted publickey for root from 203.0.113.99 port 22 ssh2\n"
	withMockOS(t, mockOSWithAuthLog(t, logContent))

	cfg := &config.Config{StatePath: statePath}
	findings := CheckIPReputation(context.Background(), cfg, nil)

	hasCritical := false
	sourceIP := ""
	for _, f := range findings {
		if f.Check == "ip_reputation" && f.Severity == alert.Critical &&
			strings.Contains(f.Message, "203.0.113.99") {
			hasCritical = true
			sourceIP = f.SourceIP
			break
		}
	}
	if !hasCritical {
		t.Errorf("expected critical ip_reputation finding for cached score 90, got: %+v", findings)
	}
	if sourceIP != "203.0.113.99" {
		t.Errorf("SourceIP = %q, want 203.0.113.99", sourceIP)
	}
}

func TestCheckIPReputationThreatDBFindingCarriesSourceIP(t *testing.T) {
	statePath := t.TempDir()
	restoreThreatDB := SetGlobalThreatDBForTest(statePath)
	t.Cleanup(restoreThreatDB)
	GetThreatDB().badIPs["203.0.113.44"] = "test-feed"

	logContent := "Apr 14 10:00:00 host sshd[1]: Accepted publickey for root from 203.0.113.44 port 22 ssh2\n"
	withMockOS(t, mockOSWithAuthLog(t, logContent))

	cfg := &config.Config{StatePath: statePath}
	findings := CheckIPReputation(context.Background(), cfg, nil)

	for _, f := range findings {
		if f.Check == "ip_reputation" && strings.Contains(f.Message, "203.0.113.44") {
			if f.SourceIP != "203.0.113.44" {
				t.Errorf("SourceIP = %q, want 203.0.113.44", f.SourceIP)
			}
			return
		}
	}
	t.Fatalf("expected threat DB ip_reputation finding, got: %+v", findings)
}

// --- CheckIPReputation: cache hit with low score → no finding -------

func TestCheckIPReputationCachedLowScoreNoFinding(t *testing.T) {
	statePath := t.TempDir()
	cache := &reputationCache{Entries: map[string]*reputationEntry{
		"203.0.113.50": {
			Score:     20, // below threshold (50)
			Category:  "Unknown",
			CheckedAt: time.Now(),
		},
	}}
	saveReputationCache(statePath, cache)

	logContent := "Apr 14 10:00:00 host sshd[1]: Accepted publickey for root from 203.0.113.50 port 22 ssh2\n"
	withMockOS(t, mockOSWithAuthLog(t, logContent))

	cfg := &config.Config{StatePath: statePath}
	findings := CheckIPReputation(context.Background(), cfg, nil)
	for _, f := range findings {
		if f.Check == "ip_reputation" && strings.Contains(f.Message, "203.0.113.50") {
			t.Errorf("low cached score should not emit finding: %+v", f)
		}
	}
}

// --- CheckIPReputation: AbuseIPDB query for unknown IP --------------

func TestCheckIPReputationFreshLookupHighScoreEmits(t *testing.T) {
	withTestAbuseIPDB(t, func(w http.ResponseWriter, r *http.Request) {
		// Return a high-confidence score so the function emits.
		_, _ = fmt.Fprintln(w, `{"data":{"abuseConfidenceScore":85,"usageType":"Compromised Server"}}`)
	})

	statePath := t.TempDir()
	logContent := "Apr 14 10:00:00 host sshd[1]: Accepted publickey for root from 198.51.100.7 port 22 ssh2\n"
	withMockOS(t, mockOSWithAuthLog(t, logContent))

	cfg := &config.Config{StatePath: statePath}
	cfg.Reputation.AbuseIPDBKey = "test-key"

	findings := CheckIPReputation(context.Background(), cfg, nil)
	hasCritical := false
	for _, f := range findings {
		if f.Check == "ip_reputation" && f.Severity == alert.Critical &&
			strings.Contains(f.Message, "198.51.100.7") {
			hasCritical = true
			break
		}
	}
	if !hasCritical {
		t.Errorf("expected critical finding for fresh lookup with score 85, got: %+v", findings)
	}
}

// --- CheckIPReputation: AbuseIPDB query for unknown IP, low score ---

func TestCheckIPReputationFreshLookupLowScoreNoFinding(t *testing.T) {
	withTestAbuseIPDB(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintln(w, `{"data":{"abuseConfidenceScore":10,"usageType":"ISP"}}`)
	})

	statePath := t.TempDir()
	logContent := "Apr 14 10:00:00 host sshd[1]: Accepted publickey for root from 198.51.100.42 port 22 ssh2\n"
	withMockOS(t, mockOSWithAuthLog(t, logContent))

	cfg := &config.Config{StatePath: statePath}
	cfg.Reputation.AbuseIPDBKey = "test-key"

	findings := CheckIPReputation(context.Background(), cfg, nil)
	for _, f := range findings {
		if strings.Contains(f.Message, "198.51.100.42") {
			t.Errorf("low score fresh lookup should not emit: %+v", f)
		}
	}
}

func TestCheckIPReputationRspamdOnlyEmitsWithoutAbuseKey(t *testing.T) {
	rspamdCalls := 0
	withDefaultHTTPTransport(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rspamdCalls++
		if r.URL.Path != "/history" {
			t.Fatalf("expected /history request, got %s", r.URL.Path)
		}
		_, _ = fmt.Fprintln(w, `{"rows":[{"ip":"198.51.100.77","action":"reject","score":8}]}`)
	}))

	statePath := t.TempDir()
	logContent := "Apr 14 10:00:00 host sshd[1]: Accepted publickey for root from 198.51.100.77 port 22 ssh2\n"
	withMockOS(t, mockOSWithAuthLog(t, logContent))

	cfg := &config.Config{StatePath: statePath}
	cfg.Reputation.Rspamd.Enabled = true
	cfg.Reputation.Rspamd.URL = localHTTPTestURL

	findings := CheckIPReputation(context.Background(), cfg, nil)
	hasCritical := false
	for _, f := range findings {
		if f.Check == "ip_reputation" && f.Severity == alert.Critical &&
			strings.Contains(f.Message, "198.51.100.77") &&
			strings.Contains(f.Message, "Rspamd score") {
			hasCritical = true
			break
		}
	}
	if !hasCritical {
		t.Fatalf("expected critical rspamd-backed finding, got: %+v", findings)
	}
	if rspamdCalls == 0 {
		t.Fatal("expected rspamd history lookup")
	}
}

func TestCheckIPReputationUpstreamOnlyEmitsWithoutAbuseKey(t *testing.T) {
	upstreamCalls := 0
	withDefaultHTTPTransport(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalls++
		if r.URL.Path != "/lookup" {
			t.Fatalf("expected /lookup request, got %s", r.URL.Path)
		}
		if got := r.URL.Query().Get("ip"); got != "198.51.100.79" {
			t.Fatalf("expected ip=198.51.100.79, got %q", got)
		}
		if r.Header.Get("Authorization") != "Bearer upstream-token" {
			t.Fatalf("expected upstream bearer token, got %q", r.Header.Get("Authorization"))
		}
		_, _ = fmt.Fprintln(w, `{"ip":"198.51.100.79","score":80,"source":"panel"}`)
	}))

	statePath := t.TempDir()
	logContent := "Apr 14 10:00:00 host sshd[1]: Accepted publickey for root from 198.51.100.79 port 22 ssh2\n"
	withMockOS(t, mockOSWithAuthLog(t, logContent))

	cfg := &config.Config{StatePath: statePath}
	cfg.Reputation.Upstream.Enabled = true
	cfg.Reputation.Upstream.URL = localHTTPTestURL
	cfg.Reputation.Upstream.Token = "upstream-token"

	findings := CheckIPReputation(context.Background(), cfg, nil)
	hasCritical := false
	for _, f := range findings {
		if f.Check == "ip_reputation" && f.Severity == alert.Critical &&
			strings.Contains(f.Message, "198.51.100.79") &&
			strings.Contains(f.Message, "Upstream score") {
			hasCritical = true
			break
		}
	}
	if !hasCritical {
		t.Fatalf("expected critical upstream-backed finding, got: %+v", findings)
	}
	if upstreamCalls == 0 {
		t.Fatal("expected upstream lookup")
	}
}

func TestCheckIPReputationRspamdEmitsWhenAbuseErrors(t *testing.T) {
	withTestAbuseIPDB(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = fmt.Fprintln(w, `{"errors":[{"detail":"temporary failure"}]}`)
	})
	withDefaultHTTPTransport(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintln(w, `{"rows":[{"ip":"198.51.100.88","action":"reject","score":8}]}`)
	}))

	statePath := t.TempDir()
	logContent := "Apr 14 10:00:00 host sshd[1]: Accepted publickey for root from 198.51.100.88 port 22 ssh2\n"
	withMockOS(t, mockOSWithAuthLog(t, logContent))

	cfg := &config.Config{StatePath: statePath}
	cfg.Reputation.AbuseIPDBKey = "test-key"
	cfg.Reputation.Rspamd.Enabled = true
	cfg.Reputation.Rspamd.URL = localHTTPTestURL

	findings := CheckIPReputation(context.Background(), cfg, nil)
	for _, f := range findings {
		if f.Check == "ip_reputation" &&
			strings.Contains(f.Message, "198.51.100.88") &&
			strings.Contains(f.Message, "Rspamd score") {
			return
		}
	}
	t.Fatalf("expected rspamd finding despite AbuseIPDB error, got: %+v", findings)
}

// --- CheckIPReputation: AbuseIPDB returns 429 → quota exhausted -----

func TestCheckIPReputationQuotaExhaustedStopsLookups(t *testing.T) {
	// AbuseIPDB queries fan out up to maxQueriesPerCycle in parallel
	// (roadmap item 7.2). Three pending IPs may all see a 429 before
	// any worker sets the in-cycle quota flag, but the per-cycle cap
	// still bounds the total. The atomic counter is required because
	// the handler is now hit concurrently.
	var calls atomic.Int64
	withTestAbuseIPDB(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusTooManyRequests)
	})

	statePath := t.TempDir()
	logContent := strings.Join([]string{
		"Apr 14 10:00:00 host sshd[1]: Accepted publickey for x from 198.51.100.1 port 22 ssh2",
		"Apr 14 10:00:01 host sshd[1]: Accepted publickey for x from 198.51.100.2 port 22 ssh2",
		"Apr 14 10:00:02 host sshd[1]: Accepted publickey for x from 198.51.100.3 port 22 ssh2",
	}, "\n") + "\n"
	withMockOS(t, mockOSWithAuthLog(t, logContent))

	cfg := &config.Config{StatePath: statePath}
	cfg.Reputation.AbuseIPDBKey = "test-key"

	_ = CheckIPReputation(context.Background(), cfg, nil)
	if got := calls.Load(); got < 1 || got > maxQueriesPerCycle {
		t.Errorf("expected 1..%d AbuseIPDB calls under parallel fan-out, got %d", maxQueriesPerCycle, got)
	}
}

// --- CheckIPReputation: respects per-cycle query limit --------------

func TestCheckIPReputationRespectsPerCycleLimit(t *testing.T) {
	// AbuseIPDB queries now run in parallel (roadmap item 7.2), so the
	// test handler must use an atomic counter; a plain int++ would
	// trigger the race detector once two workers hit the server.
	var calls atomic.Int64
	withTestAbuseIPDB(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		_, _ = fmt.Fprintln(w, `{"data":{"abuseConfidenceScore":10}}`)
	})

	statePath := t.TempDir()
	// 10 IPs surfaced; the function should stop after maxQueriesPerCycle.
	var lines []string
	for i := 1; i <= 10; i++ {
		lines = append(lines, fmt.Sprintf("Apr 14 10:00:00 host sshd[1]: Accepted publickey for x from 198.51.100.%d port 22 ssh2", i))
	}
	withMockOS(t, mockOSWithAuthLog(t, strings.Join(lines, "\n")+"\n"))

	cfg := &config.Config{StatePath: statePath}
	cfg.Reputation.AbuseIPDBKey = "test-key"

	_ = CheckIPReputation(context.Background(), cfg, nil)
	if got := calls.Load(); got > maxQueriesPerCycle {
		t.Errorf("expected <= %d API calls per cycle, got %d", maxQueriesPerCycle, got)
	}
}
