package checks

import (
	"slices"
	"testing"
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
