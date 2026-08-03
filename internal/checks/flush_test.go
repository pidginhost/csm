package checks

import (
	"testing"
	"time"
)

// An operator flush must clear the auto-block bookkeeping too: leftover
// ThreatDB temp rows re-flag every flushed IP through ip_reputation on the
// next scan and re-block it, silently undoing the flush.
func TestFlushAutoBlockStateClearsTrackerAndThreatRows(t *testing.T) {
	withTestThreatStore(t)
	restore := SetGlobalThreatDBForTest(t.TempDir())
	t.Cleanup(restore)

	statePath := t.TempDir()
	saveBlockState(statePath, &blockState{
		IPs: []blockedIP{
			{IP: "203.0.113.20", Reason: "r", ExpiresAt: time.Now().Add(time.Hour)},
			{IP: "203.0.113.21", Reason: "r", ExpiresAt: time.Now().Add(time.Hour)},
		},
		Pending: []pendingIP{{IP: "203.0.113.22", Reason: "queued", QueuedAt: time.Now()}},
	})
	tdb := GetThreatDB()
	tdb.AddTemporary("203.0.113.20", "r", time.Hour)
	tdb.AddTemporary("203.0.113.23", "engine-only", time.Hour)

	// 203.0.113.23 is in the engine's pre-flush list but not the local
	// tracker; 203.0.113.21 only in the tracker. Both must be cleaned.
	FlushAutoBlockState(statePath, []string{"203.0.113.20", "203.0.113.23"})

	state := loadBlockState(statePath)
	if len(state.IPs) != 0 {
		t.Errorf("tracker IPs = %+v, want cleared", state.IPs)
	}
	if len(state.Pending) != 1 || state.Pending[0].IP != "203.0.113.22" {
		t.Errorf("pending = %+v, want preserved (queued IPs are not blocks)", state.Pending)
	}
	if _, found := tdb.Lookup("203.0.113.20"); found {
		t.Error("threat row for flushed IP survived; flush would self-revert")
	}
	if _, found := tdb.Lookup("203.0.113.23"); found {
		t.Error("threat row for engine-only flushed IP survived")
	}
}
