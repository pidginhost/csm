package checks

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/store"
)

// withGlobalStore opens a temporary bbolt store, installs it as the global
// singleton, and returns a cleanup function.
func withGlobalStore(t *testing.T) *store.DB {
	t.Helper()
	sdb, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	store.SetGlobal(sdb)
	t.Cleanup(func() {
		store.SetGlobal(nil)
		_ = sdb.Close()
	})
	return sdb
}

// TestNextUTCMidnight verifies the quota-reset boundary is the next
// 00:00 UTC regardless of local timezone.
func TestNextUTCMidnight(t *testing.T) {
	cases := []struct {
		name string
		in   time.Time
		want time.Time
	}{
		{
			name: "mid-day UTC",
			in:   time.Date(2026, 4, 18, 14, 33, 7, 0, time.UTC),
			want: time.Date(2026, 4, 19, 0, 0, 0, 0, time.UTC),
		},
		{
			name: "just-before UTC midnight",
			in:   time.Date(2026, 4, 18, 23, 59, 59, 0, time.UTC),
			want: time.Date(2026, 4, 19, 0, 0, 0, 0, time.UTC),
		},
		{
			name: "exactly UTC midnight advances to next day",
			in:   time.Date(2026, 4, 18, 0, 0, 0, 0, time.UTC),
			want: time.Date(2026, 4, 19, 0, 0, 0, 0, time.UTC),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := nextUTCMidnight(tc.in)
			if !got.Equal(tc.want) {
				t.Fatalf("nextUTCMidnight(%v) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

// withLowDailyCap lowers maxDailyAbuseQueries for the duration of a test
// so tests don't burn 900 bbolt transactions proving the circuit breaker.
func withLowDailyCap(t *testing.T, cap int) {
	t.Helper()
	orig := maxDailyAbuseQueries
	maxDailyAbuseQueries = cap
	t.Cleanup(func() { maxDailyAbuseQueries = orig })
}

// TestAbuseQuotaReady covers the three states: no store (allow), active
// backoff window (deny), daily counter exceeded (deny).
func TestAbuseQuotaReady(t *testing.T) {
	withLowDailyCap(t, 3)

	// Nil store: always ready.
	if !abuseQuotaReady(nil, time.Now()) {
		t.Fatal("nil store must report ready")
	}

	sdb := withGlobalStore(t)
	now := time.Now()

	// Fresh store: ready.
	if !abuseQuotaReady(sdb, now) {
		t.Fatal("fresh store should be ready")
	}

	// Backoff active: not ready.
	if err := sdb.SetAbuseQuotaExhaustedUntil(now.Add(30 * time.Minute)); err != nil {
		t.Fatalf("SetAbuseQuotaExhaustedUntil: %v", err)
	}
	if abuseQuotaReady(sdb, now) {
		t.Fatal("active backoff should block readiness")
	}

	// Time past the backoff, counter still at 0: ready again.
	if !abuseQuotaReady(sdb, now.Add(61*time.Minute)) {
		t.Fatal("expired backoff should not block readiness")
	}

	// Reset backoff, bump count to cap, expect not ready.
	if err := sdb.SetAbuseQuotaExhaustedUntil(time.Time{}); err != nil {
		t.Fatalf("reset backoff: %v", err)
	}
	day := now.UTC().Format("2006-01-02")
	for i := 0; i < maxDailyAbuseQueries; i++ {
		sdb.IncrementAbuseQueryCount(day)
	}
	if abuseQuotaReady(sdb, now) {
		t.Fatalf("daily cap reached at %d, should block", maxDailyAbuseQueries)
	}
}

// TestCheckIPReputationPersistsQuotaOn429 verifies a 429 response
// persists a quota-exhausted-until timestamp so subsequent cycles skip
// the API entirely.
//
// CheckIPReputation now fans out up to maxQueriesPerCycle tier-4
// AbuseIPDB queries in parallel (roadmap item 7.2), so the first cycle
// fires one call per pending IP (here: 2) before any worker observes
// the 429. The second cycle must then skip the API; that is the load
// bearing invariant for billing safety.
func TestCheckIPReputationPersistsQuotaOn429(t *testing.T) {
	sdb := withGlobalStore(t)

	var calls atomic.Int64
	withTestAbuseIPDB(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusTooManyRequests)
	})

	logContent := strings.Join([]string{
		"Apr 18 10:00:00 host sshd[1]: Accepted publickey for x from 198.51.100.1 port 22 ssh2",
		"Apr 18 10:00:01 host sshd[1]: Accepted publickey for x from 198.51.100.2 port 22 ssh2",
	}, "\n") + "\n"
	withMockOS(t, mockOSWithSecureLog(t, logContent))

	cfg := &config.Config{StatePath: t.TempDir()}
	cfg.Reputation.AbuseIPDBKey = "test-key"

	_ = CheckIPReputation(context.Background(), cfg, nil)
	first := calls.Load()
	if first < 1 || first > 2 {
		t.Fatalf("first cycle: want 1..2 calls (parallel fan-out across 2 pending IPs), got %d", first)
	}

	until := sdb.AbuseQuotaExhaustedUntil()
	if until.IsZero() {
		t.Fatal("429 should persist AbuseQuotaExhaustedUntil")
	}
	if !until.After(time.Now()) {
		t.Fatalf("AbuseQuotaExhaustedUntil = %v, want future time", until)
	}

	// Second cycle: persisted AbuseQuotaExhaustedUntil short-circuits
	// abuseQuotaReady so zero additional calls should reach the API.
	_ = CheckIPReputation(context.Background(), cfg, nil)
	if calls.Load() != first {
		t.Fatalf("second cycle: expected 0 additional calls (persisted backoff), got %d total (was %d)", calls.Load(), first)
	}
}

// TestCheckIPReputationRespectsDailyCap verifies the per-day circuit
// breaker prevents queries once the persisted counter reaches the cap.
func TestCheckIPReputationRespectsDailyCap(t *testing.T) {
	withLowDailyCap(t, 3)
	sdb := withGlobalStore(t)

	// Pre-load the counter to the cap for today.
	day := time.Now().UTC().Format("2006-01-02")
	for i := 0; i < maxDailyAbuseQueries; i++ {
		sdb.IncrementAbuseQueryCount(day)
	}

	calls := 0
	withTestAbuseIPDB(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		_, _ = fmt.Fprintln(w, `{"data":{"abuseConfidenceScore":10}}`)
	})

	logContent := "Apr 18 10:00:00 host sshd[1]: Accepted publickey for x from 198.51.100.9 port 22 ssh2\n"
	withMockOS(t, mockOSWithSecureLog(t, logContent))

	cfg := &config.Config{StatePath: t.TempDir()}
	cfg.Reputation.AbuseIPDBKey = "test-key"

	_ = CheckIPReputation(context.Background(), cfg, nil)
	if calls != 0 {
		t.Fatalf("expected 0 calls when daily cap already hit, got %d", calls)
	}
}

// TestCheckIPReputationIncrementsDailyCounter verifies the counter is
// bumped before the API call so it is accounted even on crashes.
func TestCheckIPReputationIncrementsDailyCounter(t *testing.T) {
	sdb := withGlobalStore(t)

	withTestAbuseIPDB(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintln(w, `{"data":{"abuseConfidenceScore":10}}`)
	})

	logContent := strings.Join([]string{
		"Apr 18 10:00:00 host sshd[1]: Accepted publickey for x from 198.51.100.1 port 22 ssh2",
		"Apr 18 10:00:01 host sshd[1]: Accepted publickey for x from 198.51.100.2 port 22 ssh2",
		"Apr 18 10:00:02 host sshd[1]: Accepted publickey for x from 198.51.100.3 port 22 ssh2",
	}, "\n") + "\n"
	withMockOS(t, mockOSWithSecureLog(t, logContent))

	cfg := &config.Config{StatePath: t.TempDir()}
	cfg.Reputation.AbuseIPDBKey = "test-key"

	_ = CheckIPReputation(context.Background(), cfg, nil)

	day := time.Now().UTC().Format("2006-01-02")
	got := sdb.AbuseQueryCount(day)
	if got != 3 {
		t.Fatalf("AbuseQueryCount = %d, want 3", got)
	}
}

func TestCheckIPReputationNearDailyCapReservesOnlyRemainingSlots(t *testing.T) {
	withLowDailyCap(t, 3)
	sdb := withGlobalStore(t)

	day := time.Now().UTC().Format("2006-01-02")
	for i := 0; i < 2; i++ {
		sdb.IncrementAbuseQueryCount(day)
	}

	var abuseCalls atomic.Int64
	withTestAbuseIPDB(t, func(w http.ResponseWriter, r *http.Request) {
		abuseCalls.Add(1)
		_, _ = fmt.Fprintln(w, `{"data":{"abuseConfidenceScore":10,"usageType":"ISP"}}`)
	})

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := r.URL.Query().Get("ip")
		_, _ = fmt.Fprintf(w, `{"ip":%q,"score":80,"source":"panel"}`, ip)
	}))
	defer upstream.Close()

	logContent := strings.Join([]string{
		"Apr 18 10:00:00 host sshd[1]: Accepted publickey for x from 198.51.100.1 port 22 ssh2",
		"Apr 18 10:00:01 host sshd[1]: Accepted publickey for x from 198.51.100.2 port 22 ssh2",
		"Apr 18 10:00:02 host sshd[1]: Accepted publickey for x from 198.51.100.3 port 22 ssh2",
	}, "\n") + "\n"
	withMockOS(t, mockOSWithSecureLog(t, logContent))

	cfg := &config.Config{StatePath: t.TempDir()}
	cfg.Reputation.AbuseIPDBKey = "test-key"
	cfg.Reputation.Upstream.Enabled = true
	cfg.Reputation.Upstream.URL = upstream.URL

	findings := CheckIPReputation(context.Background(), cfg, nil)
	if got := abuseCalls.Load(); got != 1 {
		t.Fatalf("AbuseIPDB calls = %d, want only the one remaining daily slot", got)
	}
	if got := sdb.AbuseQueryCount(day); got != 3 {
		t.Fatalf("AbuseQueryCount = %d, want daily cap 3", got)
	}

	upstreamFindings := 0
	for _, f := range findings {
		if f.Check == "ip_reputation" && strings.Contains(f.Message, "Upstream score") {
			upstreamFindings++
		}
	}
	if upstreamFindings != 3 {
		t.Fatalf("Upstream findings = %d, want one for each pending IP; got %+v", upstreamFindings, findings)
	}
}

// TestCheckIPReputationErrorCacheExpiresQuickly verifies that transient
// errors are cached with a CheckedAt in the past such that the entry
// expires after errorCacheExpiry (~1h), not ~11h as with the pre-fix
// formula. We assert the stored CheckedAt is strictly before time.Now().
func TestCheckIPReputationErrorCacheExpiresQuickly(t *testing.T) {
	// Return a malformed JSON so queryAbuseIPDB returns a non-quota error.
	withTestAbuseIPDB(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})

	statePath := t.TempDir()
	logContent := "Apr 18 10:00:00 host sshd[1]: Accepted publickey for x from 198.51.100.77 port 22 ssh2\n"
	withMockOS(t, mockOSWithSecureLog(t, logContent))

	cfg := &config.Config{StatePath: statePath}
	cfg.Reputation.AbuseIPDBKey = "test-key"

	before := time.Now()
	_ = CheckIPReputation(context.Background(), cfg, nil)
	after := time.Now()

	cache := loadReputationCache(statePath)
	entry, ok := cache.Entries["198.51.100.77"]
	if !ok {
		t.Fatal("expected error entry cached for 198.51.100.77")
	}
	if entry.Score != -1 {
		t.Fatalf("error-entry Score = %d, want -1", entry.Score)
	}
	// CheckedAt must be in the past, offset ~= -(cacheExpiry - errorCacheExpiry).
	if !entry.CheckedAt.Before(before) {
		t.Fatalf("CheckedAt %v should be before test start %v (error cache must shift into past)",
			entry.CheckedAt, before)
	}
	// Expect an offset close to -(5h) — allow 10s of slop for test runtime.
	wantOffset := -(cacheExpiry - errorCacheExpiry)
	gotOffset := entry.CheckedAt.Sub(after)
	drift := gotOffset - wantOffset
	if drift < -10*time.Second || drift > 10*time.Second {
		t.Fatalf("CheckedAt offset = %v, want ≈ %v", gotOffset, wantOffset)
	}
	// Age as perceived by the Tier-3 check: entry should read as almost expired.
	age := time.Since(entry.CheckedAt)
	if age < (cacheExpiry-errorCacheExpiry)-10*time.Second || age > (cacheExpiry-errorCacheExpiry)+10*time.Second {
		t.Fatalf("perceived age = %v, want ≈ %v", age, cacheExpiry-errorCacheExpiry)
	}
}
