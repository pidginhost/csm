package threat

import (
	"testing"
	"time"
)

// Legacy bookkeeping must not restore a blocked verdict that the firewall
// view holds back for recovery, for either single or batch lookups.
func TestLookupDoesNotReviveUnverifiedBlocksFromLegacy(t *testing.T) {
	for _, expires := range []time.Time{{}, time.Now().Add(time.Hour), time.Now().Add(-time.Hour)} {
		dir := t.TempDir()
		writeEngineBlockState(t, dir, []map[string]any{
			{"ip": "192.0.2.65", "reason": "unknown", "action_id": "act_held", "unverified": true, "expires_at": expires},
			{"ip": "192.0.2.66", "reason": "operator"},
		})
		writeBlockedIPsFile(t, dir, []map[string]any{
			{"ip": "192.0.2.65", "reason": "legacy bookkeeping", "expires_at": time.Now().Add(time.Hour)},
		})
		results := append([]*IPIntelligence{Lookup("192.0.2.65", dir)}, LookupBatch([]string{"192.0.2.65", "192.0.2.66"}, dir)...)
		for _, intel := range results[:2] {
			if intel.CurrentlyBlocked || intel.Verdict == "blocked" || intel.BlockReason != "" || intel.BlockPermanent || intel.BlockedAt != nil || intel.BlockExpiresAt != nil {
				t.Errorf("expiry %v: held block revived from legacy bookkeeping: %+v", expires, intel)
			}
		}
		if !results[2].CurrentlyBlocked || results[2].Verdict != "blocked" || results[2].BlockReason != "operator" {
			t.Errorf("enforced operator block missing: %+v", results[2])
		}
	}
}
