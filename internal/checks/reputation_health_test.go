package checks

import (
	"context"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
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
	if err := sdb.SetAbuseQuotaExhaustedUntil(time.Now().Add(6 * time.Hour)); err != nil {
		t.Fatal(err)
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
