package checks

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/state"
)

// The attack database's score is for display and ranking only. Every input
// that could raise it to the alert threshold was removed as a false-positive
// source, and a derived score is never an independent block source. No tier
// runs the scan that turned it into local_threat_score findings, and a
// completed critical scan still clears the findings older versions stored.
func TestThreatScoreScanIsRetired(t *testing.T) {
	for _, tier := range []Tier{TierCritical, TierDeep} {
		for _, nc := range checksForTier(tier) {
			if nc.name == "local_threat_score" {
				t.Errorf("tier %v still schedules the attack database score scan", tier)
			}
		}
	}
	if !slices.Contains(LatestPurgeCheckNamesForTier(TierCritical), "local_threat_score") {
		t.Error("a completed critical scan no longer clears local_threat_score findings stored by older versions")
	}
}

func TestRetiredThreatScoreDisableKeepsReputationRunning(t *testing.T) {
	cfg := &config.Config{DisabledChecks: []string{"local_threat_score"}}
	check := namedCheck{name: "ip_reputation", fn: func(ctx context.Context, cfg *config.Config, st *state.Store) []alert.Finding {
		return []alert.Finding{
			{Check: "ip_reputation", Severity: alert.High, SourceIP: "192.0.2.7"},
			{Check: "reputation_quota_exhausted", Severity: alert.Warning},
			{Check: "threat_feed_stale", Severity: alert.Warning},
		}
	}}
	findings, purge := runParallelWithContext(context.Background(), cfg, nil, []namedCheck{check}, string(TierCritical), true)
	for _, name := range []string{"ip_reputation", "reputation_quota_exhausted", "threat_feed_stale"} {
		if !containsFindingCheck(findings, name) {
			t.Errorf("retired disable value stopped %s: %+v", name, findings)
		}
	}
	if !slices.Contains(purge, "local_threat_score") {
		t.Errorf("retired disable value prevented legacy finding cleanup: %v", purge)
	}
	if !slices.Contains(DisabledCheckConfigNames(), "local_threat_score") {
		t.Error("existing configs with the retired disable value are rejected")
	}
	if off := disabledLogicalOwners(cfg); len(off) != 0 {
		t.Errorf("retired disable value disabled reputation health: %v", off)
	}
}

func TestRetiredThreatScorePurgeKeepsHistory(t *testing.T) {
	st, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	legacy := alert.Finding{Check: "local_threat_score", Severity: alert.Critical, SourceIP: "192.0.2.8", Message: "legacy score", Timestamp: time.Now()}
	unrelated := alert.Finding{Check: "webshell", Severity: alert.Critical, Message: "unrelated", Timestamp: time.Now()}
	st.SetLatestFindings([]alert.Finding{legacy, unrelated})
	st.AppendHistory([]alert.Finding{legacy})
	check := namedCheck{name: "ip_reputation", fn: func(context.Context, *config.Config, *state.Store) []alert.Finding { return nil }}
	findings, purge := runParallelWithContext(context.Background(), &config.Config{}, st, []namedCheck{check}, string(TierCritical), true)
	StoreLatestScanFindings(st, purge, findings)
	if got := st.LatestFindings(); len(got) != 1 || got[0].Check != "webshell" {
		t.Fatalf("latest findings = %+v, want only the unrelated finding", got)
	}
	if history, total := st.ReadHistory(10, 0); total != 1 || len(history) != 1 || history[0].Check != "local_threat_score" {
		t.Fatalf("history = %+v (total %d), want the legacy score finding", history, total)
	}
}
