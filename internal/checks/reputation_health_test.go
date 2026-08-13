package checks

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/state"
	"github.com/pidginhost/csm/internal/store"
)

func reputationHealthConfig(t *testing.T) *config.Config {
	t.Helper()
	cfg := &config.Config{}
	cfg.StatePath = t.TempDir()
	return cfg
}

func findingWithCheck(findings []alert.Finding, check string) (alert.Finding, bool) {
	for _, f := range findings {
		if f.Check == check {
			return f, true
		}
	}
	return alert.Finding{}, false
}

// While the AbuseIPDB quota backoff is active, reputation lookups silently
// degrade to local tiers. The operator must see that blindness as a
// finding, not only a stderr line.
func TestCheckIPReputationEmitsQuotaExhaustedFinding(t *testing.T) {
	cfg := reputationHealthConfig(t)
	cfg.Reputation.AbuseIPDBKey = "test-key"
	t.Cleanup(SetGlobalThreatDBForTest(t.TempDir()))

	sdb, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	prev := store.Global()
	store.SetGlobal(sdb)
	t.Cleanup(func() {
		store.SetGlobal(prev)
		_ = sdb.Close()
	})
	if setErr := sdb.SetAbuseQuotaExhaustedUntil(time.Now().Add(6 * time.Hour)); setErr != nil {
		t.Fatal(setErr)
	}

	findings := CheckIPReputation(context.Background(), cfg, nil)
	f, ok := findingWithCheck(findings, "reputation_quota_exhausted")
	if !ok {
		t.Fatalf("findings = %+v, want a reputation_quota_exhausted finding", findings)
	}
	if f.Severity != alert.Warning {
		t.Errorf("severity = %s, want Warning", f.Severity)
	}
}

// Without an API key there is no quota to exhaust; no finding.
func TestCheckIPReputationQuotaFindingRequiresKey(t *testing.T) {
	cfg := reputationHealthConfig(t)
	t.Cleanup(SetGlobalThreatDBForTest(t.TempDir()))

	sdb, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	prev := store.Global()
	store.SetGlobal(sdb)
	t.Cleanup(func() {
		store.SetGlobal(prev)
		_ = sdb.Close()
	})
	if err := sdb.SetAbuseQuotaExhaustedUntil(time.Now().Add(6 * time.Hour)); err != nil {
		t.Fatal(err)
	}

	findings := CheckIPReputation(context.Background(), cfg, nil)
	if _, ok := findingWithCheck(findings, "reputation_quota_exhausted"); ok {
		t.Fatalf("findings = %+v, want no quota finding without an API key", findings)
	}
}

// Threat feeds that once loaded but have not refreshed in over a week mean
// tier-2 lookups run on stale data; surface it.
func TestCheckIPReputationEmitsFeedStaleFinding(t *testing.T) {
	cfg := reputationHealthConfig(t)
	t.Cleanup(SetGlobalThreatDBForTest(t.TempDir()))
	GetThreatDB().LastUpdated = time.Now().Add(-8 * 24 * time.Hour)

	findings := CheckIPReputation(context.Background(), cfg, nil)
	f, ok := findingWithCheck(findings, "threat_feed_stale")
	if !ok {
		t.Fatalf("findings = %+v, want a threat_feed_stale finding", findings)
	}
	if f.Severity != alert.Warning {
		t.Errorf("severity = %s, want Warning", f.Severity)
	}
}

// A threat DB that has never loaded feeds (fresh install, first download
// still pending) must not alarm.
func TestCheckIPReputationFeedStaleSilentWhenNeverLoaded(t *testing.T) {
	cfg := reputationHealthConfig(t)
	t.Cleanup(SetGlobalThreatDBForTest(t.TempDir()))

	findings := CheckIPReputation(context.Background(), cfg, nil)
	if _, ok := findingWithCheck(findings, "threat_feed_stale"); ok {
		t.Fatalf("findings = %+v, want no stale finding for a never-loaded feed set", findings)
	}
}

func TestReputationHealthThrottleSurvivesRestart(t *testing.T) {
	withMockOS(t, &mockOS{})
	statePath := t.TempDir()
	cfg := &config.Config{StatePath: statePath}
	cfg.Reputation.AbuseIPDBKey = "test-key"
	t.Cleanup(SetGlobalThreatDBForTest(t.TempDir()))

	sdb, err := store.Open(statePath)
	if err != nil {
		t.Fatal(err)
	}
	previousDB := store.Global()
	store.SetGlobal(sdb)
	t.Cleanup(func() {
		store.SetGlobal(previousDB)
		_ = sdb.Close()
	})
	if setErr := sdb.SetAbuseQuotaExhaustedUntil(time.Now().Add(6 * time.Hour)); setErr != nil {
		t.Fatal(setErr)
	}

	firstState, err := state.Open(statePath)
	if err != nil {
		t.Fatal(err)
	}
	first := CheckIPReputation(context.Background(), cfg, firstState)
	if _, ok := findingWithCheck(first, "reputation_quota_exhausted"); !ok {
		t.Fatalf("first findings = %+v, want quota warning", first)
	}
	if closeErr := firstState.Close(); closeErr != nil {
		t.Fatal(closeErr)
	}

	reopened, err := state.Open(statePath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	second := CheckIPReputation(context.Background(), cfg, reopened)
	if _, ok := findingWithCheck(second, "reputation_quota_exhausted"); ok {
		t.Fatalf("second findings after reopen = %+v, want persisted reminder throttle", second)
	}
}

func TestReputationHealthThrottleRetainsAndClearsLatestFinding(t *testing.T) {
	st, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()

	cfg := &config.Config{}
	cfg.Reputation.AbuseIPDBKey = "test-key"
	now := time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC)
	quotaExhausted := true
	check := namedCheck{name: "ip_reputation", fn: func(ctx context.Context, cfg *config.Config, st *state.Store) []alert.Finding {
		return reputationHealthFindings(ctx, cfg, nil, st, now, quotaExhausted)
	}}

	first, firstPurge := runParallelWithContext(context.Background(), cfg, st, []namedCheck{check}, "critical", true)
	StoreLatestScanFindings(st, firstPurge, first)
	if !containsFindingCheck(st.LatestFindings(), "reputation_quota_exhausted") {
		t.Fatalf("first latest findings = %+v, want quota warning", st.LatestFindings())
	}

	now = now.Add(time.Minute)
	second, secondPurge := runParallelWithContext(context.Background(), cfg, st, []namedCheck{check}, "critical", true)
	if len(second) != 0 {
		t.Fatalf("second findings = %+v, want reminder throttled", second)
	}
	if slices.Contains(secondPurge, "reputation_quota_exhausted") {
		t.Fatalf("throttled active condition entered purge list: %v", secondPurge)
	}
	StoreLatestScanFindings(st, secondPurge, second)
	if !containsFindingCheck(st.LatestFindings(), "reputation_quota_exhausted") {
		t.Fatalf("throttled condition disappeared from latest findings: %+v", st.LatestFindings())
	}

	quotaExhausted = false
	third, thirdPurge := runParallelWithContext(context.Background(), cfg, st, []namedCheck{check}, "critical", true)
	if !slices.Contains(thirdPurge, "reputation_quota_exhausted") {
		t.Fatalf("cleared condition missing from purge list: %v", thirdPurge)
	}
	StoreLatestScanFindings(st, thirdPurge, third)
	if containsFindingCheck(st.LatestFindings(), "reputation_quota_exhausted") {
		t.Fatalf("cleared quota warning remains in latest findings: %+v", st.LatestFindings())
	}
}

func TestDisablingReputationClearsReminderThrottle(t *testing.T) {
	st, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()

	now := time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC)
	cfg := &config.Config{}
	cfg.Reputation.AbuseIPDBKey = "test-key"
	check := namedCheck{name: "ip_reputation", fn: func(ctx context.Context, cfg *config.Config, st *state.Store) []alert.Finding {
		return reputationHealthFindings(ctx, cfg, nil, st, now, true)
	}}

	first, firstPurge := runParallelWithContext(context.Background(), cfg, st, []namedCheck{check}, "critical", true)
	StoreLatestScanFindings(st, firstPurge, first)
	if _, ok := st.GetRaw(reputationQuotaStateKey); !ok {
		t.Fatal("first warning did not persist its reminder claim")
	}

	cfg.DisabledChecks = []string{"ip_reputation"}
	disabled, disabledPurge := runParallelWithContext(context.Background(), cfg, st, []namedCheck{check}, "critical", true)
	StoreLatestScanFindings(st, disabledPurge, disabled)
	if _, ok := st.GetRaw(reputationQuotaStateKey); ok {
		t.Fatal("disabling ip_reputation retained its reminder claim")
	}
	if containsFindingCheck(st.LatestFindings(), "reputation_quota_exhausted") {
		t.Fatalf("disabled warning remains in latest findings: %+v", st.LatestFindings())
	}

	cfg.DisabledChecks = nil
	reenabled, _ := runParallelWithContext(context.Background(), cfg, st, []namedCheck{check}, "critical", true)
	if _, ok := findingWithCheck(reenabled, "reputation_quota_exhausted"); !ok {
		t.Fatalf("re-enabled persistent condition stayed throttled: %+v", reenabled)
	}
}

func TestFeedStaleWallClockComparisonRecoversFromFutureTimestamp(t *testing.T) {
	last := time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC)
	clockSteppedBack := last.Add(-time.Hour)
	if feedRefreshStale(last, clockSteppedBack) {
		t.Fatal("future refresh timestamp must not produce a stale warning after a backward clock step")
	}
	if !feedRefreshStale(last, last.Add(8*24*time.Hour)) {
		t.Fatal("future timestamp permanently suppressed a real stale condition")
	}
}

func TestAbuseQuotaExhaustionLeavesRspamdActive(t *testing.T) {
	withLowDailyCap(t, 1)
	sdb := withGlobalStore(t)
	sdb.IncrementAbuseQueryCount(time.Now().UTC().Format("2006-01-02"))

	var abuseCalls atomic.Int64
	withTestAbuseIPDB(t, func(w http.ResponseWriter, r *http.Request) {
		abuseCalls.Add(1)
		_, _ = fmt.Fprintln(w, `{"data":{"abuseConfidenceScore":90}}`)
	})
	var rspamdCalls atomic.Int64
	withDefaultHTTPTransport(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rspamdCalls.Add(1)
		_, _ = fmt.Fprintln(w, `{"rows":[
			{"ip":"198.51.100.201","action":"reject","score":25},
			{"ip":"198.51.100.201","action":"reject","score":31},
			{"ip":"198.51.100.201","action":"reject","score":22},
			{"ip":"198.51.100.201","action":"reject","score":27},
			{"ip":"198.51.100.201","action":"reject","score":29}]}`)
	}))

	withMockOS(t, mockOSWithAuthLog(t,
		"Apr 18 10:00:00 host sshd[1]: Accepted publickey for x from 198.51.100.201 port 22 ssh2\n"))
	cfg := &config.Config{StatePath: t.TempDir()}
	cfg.Reputation.AbuseIPDBKey = "test-key"
	cfg.Reputation.Rspamd.Enabled = true
	cfg.Reputation.Rspamd.URL = localHTTPTestURL

	findings := CheckIPReputation(context.Background(), cfg, nil)
	if got := abuseCalls.Load(); got != 0 {
		t.Fatalf("AbuseIPDB calls = %d, want none after its quota is exhausted", got)
	}
	if got := rspamdCalls.Load(); got == 0 {
		t.Fatal("rspamd was disabled by AbuseIPDB quota exhaustion")
	}
	if finding, ok := findingWithCheck(findings, "reputation_quota_exhausted"); !ok || !strings.Contains(finding.Message, "AbuseIPDB") {
		t.Fatalf("quota finding missing or misattributed: %+v", findings)
	}
	for _, finding := range findings {
		if finding.Check == "ip_reputation" && strings.Contains(finding.Message, "Rspamd score") {
			return
		}
	}
	t.Fatalf("rspamd finding missing while AbuseIPDB was exhausted: %+v", findings)
}

func TestFeedStaleFindingDoesNotTriggerReputationLookups(t *testing.T) {
	withMockOS(t, &mockOS{})
	t.Cleanup(SetGlobalThreatDBForTest(t.TempDir()))
	GetThreatDB().LastUpdated = time.Now().Add(-8 * 24 * time.Hour)

	var abuseCalls atomic.Int64
	withTestAbuseIPDB(t, func(w http.ResponseWriter, r *http.Request) {
		abuseCalls.Add(1)
		_, _ = fmt.Fprintln(w, `{"data":{"abuseConfidenceScore":90}}`)
	})
	var supplementalCalls atomic.Int64
	withDefaultHTTPTransport(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		supplementalCalls.Add(1)
		_, _ = fmt.Fprintln(w, `{"score":90}`)
	}))

	cfg := &config.Config{StatePath: t.TempDir()}
	cfg.Reputation.AbuseIPDBKey = "test-key"
	cfg.Reputation.Rspamd.Enabled = true
	cfg.Reputation.Rspamd.URL = localHTTPTestURL
	cfg.Reputation.Upstream.Enabled = true
	cfg.Reputation.Upstream.URL = localHTTPTestURL

	findings := CheckIPReputation(context.Background(), cfg, nil)
	if _, ok := findingWithCheck(findings, "threat_feed_stale"); !ok {
		t.Fatalf("findings = %+v, want stale-feed warning", findings)
	}
	if abuseCalls.Load() != 0 || supplementalCalls.Load() != 0 {
		t.Fatalf("health finding triggered lookups: abuse=%d supplemental=%d", abuseCalls.Load(), supplementalCalls.Load())
	}
}
