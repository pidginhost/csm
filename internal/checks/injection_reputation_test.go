package checks

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

// mockOSWithSecureLog returns a mockOS that serves the given content as
// /var/log/secure when osFS.Open is called with that path. ReadFile and
// other operations fall through to the real filesystem so reputation_cache
// (read via osFS.ReadFile from the test's temp StatePath) and other
// genuine file lookups succeed.
func mockOSWithSecureLog(t *testing.T, content string) *mockOS {
	t.Helper()
	tmp := filepath.Join(t.TempDir(), "secure")
	if err := os.WriteFile(tmp, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	return &mockOS{
		open: func(name string) (*os.File, error) {
			if name == "/var/log/secure" {
				return os.Open(tmp)
			}
			return os.Open(name)
		},
		stat:     os.Stat,
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

	// Surface the IP via SSH log (collectRecentIPs reads /var/log/secure
	// looking for "Accepted ... from <ip>").
	logContent := "Apr 14 10:00:00 host sshd[1]: Accepted publickey for root from 203.0.113.99 port 22 ssh2\n"
	withMockOS(t, mockOSWithSecureLog(t, logContent))

	cfg := &config.Config{StatePath: statePath}
	findings := CheckIPReputation(context.Background(), cfg, nil)

	hasCritical := false
	for _, f := range findings {
		if f.Check == "ip_reputation" && f.Severity == alert.Critical &&
			strings.Contains(f.Message, "203.0.113.99") {
			hasCritical = true
			break
		}
	}
	if !hasCritical {
		t.Errorf("expected critical ip_reputation finding for cached score 90, got: %+v", findings)
	}
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
	withMockOS(t, mockOSWithSecureLog(t, logContent))

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
	withMockOS(t, mockOSWithSecureLog(t, logContent))

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
	withMockOS(t, mockOSWithSecureLog(t, logContent))

	cfg := &config.Config{StatePath: statePath}
	cfg.Reputation.AbuseIPDBKey = "test-key"

	findings := CheckIPReputation(context.Background(), cfg, nil)
	for _, f := range findings {
		if strings.Contains(f.Message, "198.51.100.42") {
			t.Errorf("low score fresh lookup should not emit: %+v", f)
		}
	}
}

// --- CheckIPReputation: AbuseIPDB returns 429 → quota exhausted -----

func TestCheckIPReputationQuotaExhaustedStopsLookups(t *testing.T) {
	calls := 0
	withTestAbuseIPDB(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusTooManyRequests)
	})

	statePath := t.TempDir()
	// Multiple distinct IPs surface; once 429 is detected the loop sets
	// quotaExhausted=true and skips further queries.
	logContent := strings.Join([]string{
		"Apr 14 10:00:00 host sshd[1]: Accepted publickey for x from 198.51.100.1 port 22 ssh2",
		"Apr 14 10:00:01 host sshd[1]: Accepted publickey for x from 198.51.100.2 port 22 ssh2",
		"Apr 14 10:00:02 host sshd[1]: Accepted publickey for x from 198.51.100.3 port 22 ssh2",
	}, "\n") + "\n"
	withMockOS(t, mockOSWithSecureLog(t, logContent))

	cfg := &config.Config{StatePath: statePath}
	cfg.Reputation.AbuseIPDBKey = "test-key"

	_ = CheckIPReputation(context.Background(), cfg, nil)
	if calls != 1 {
		t.Errorf("expected exactly 1 AbuseIPDB call before quota detection halts further queries, got %d", calls)
	}
}

// --- CheckIPReputation: respects per-cycle query limit --------------

func TestCheckIPReputationRespectsPerCycleLimit(t *testing.T) {
	calls := 0
	withTestAbuseIPDB(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		_, _ = fmt.Fprintln(w, `{"data":{"abuseConfidenceScore":10}}`)
	})

	statePath := t.TempDir()
	// 10 IPs surfaced; the function should stop after maxQueriesPerCycle.
	var lines []string
	for i := 1; i <= 10; i++ {
		lines = append(lines, fmt.Sprintf("Apr 14 10:00:00 host sshd[1]: Accepted publickey for x from 198.51.100.%d port 22 ssh2", i))
	}
	withMockOS(t, mockOSWithSecureLog(t, strings.Join(lines, "\n")+"\n"))

	cfg := &config.Config{StatePath: statePath}
	cfg.Reputation.AbuseIPDBKey = "test-key"

	_ = CheckIPReputation(context.Background(), cfg, nil)
	if calls > maxQueriesPerCycle {
		t.Errorf("expected ≤ %d API calls per cycle, got %d", maxQueriesPerCycle, calls)
	}
}
