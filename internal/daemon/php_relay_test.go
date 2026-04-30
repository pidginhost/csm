package daemon

import (
	"testing"
	"time"
)

func TestScriptState_AppendAndPrune(t *testing.T) {
	s := newScriptState()
	now := time.Now()
	s.append(scriptEvent{At: now.Add(-90 * time.Minute), MsgID: "old", FromMismatch: true, AdditionalSignal: true})
	s.append(scriptEvent{At: now.Add(-30 * time.Minute), MsgID: "mid", FromMismatch: true, AdditionalSignal: true})
	s.append(scriptEvent{At: now, MsgID: "new", FromMismatch: true, AdditionalSignal: true})

	n := s.qualifyingCount(now.Add(-60*time.Minute), func(e scriptEvent) bool {
		return e.FromMismatch && e.AdditionalSignal
	})
	if n != 2 {
		t.Errorf("qualifyingCount within 60m = %d, want 2 (mid + new)", n)
	}
}

func TestScriptState_ActiveMsgsCap(t *testing.T) {
	s := newScriptState()
	s.maxActiveMsgs = 3
	now := time.Now()
	for _, id := range []string{"a", "b", "c", "d", "e"} {
		s.recordActive(id, now)
		now = now.Add(time.Second)
	}
	if !s.activeMsgsCapped {
		t.Errorf("expected activeMsgsCapped = true after exceeding maxActiveMsgs")
	}
	if got := len(s.activeMsgs); got > 3 {
		t.Errorf("activeMsgs len = %d, want <= 3", got)
	}
}

func TestScriptState_ActiveMsgsRemove(t *testing.T) {
	s := newScriptState()
	s.recordActive("id1", time.Now())
	s.removeActive("id1")
	if _, ok := s.activeMsgs["id1"]; ok {
		t.Errorf("id1 should be gone after removeActive")
	}
}

func TestScriptState_SnapshotActiveMsgs(t *testing.T) {
	s := newScriptState()
	now := time.Now()
	s.recordActive("a", now)
	s.recordActive("b", now)

	msgIDs, capped := s.snapshotActiveMsgs()
	if len(msgIDs) != 2 || capped {
		t.Errorf("snapshot = (%v, %v), want 2 msgIDs and capped=false", msgIDs, capped)
	}
	// Mutating the returned slice must NOT affect internal state.
	msgIDs[0] = "BOGUS"
	if _, ok := s.activeMsgs["BOGUS"]; ok {
		t.Errorf("snapshot must return a copy")
	}
}

// PruneActiveMsgs is a perScriptWindow-level helper added alongside SweepIdle.
// It iterates retained scriptStates and prunes activeMsgs entries older than
// cutoff. Called by Flow E (O2) on the 5-min ticker so still-active scripts
// don't accumulate ghost activeMsgs whose corresponding messages have left
// the queue without a "Completed" log line being parsed.
func TestPerScriptWindow_PruneActiveMsgs(t *testing.T) {
	w := newPerScriptWindow()
	s1 := w.getOrCreate("k1:/")
	s2 := w.getOrCreate("k2:/")
	now := time.Now()
	s1.recordActive("old1", now.Add(-26*time.Hour))
	s1.recordActive("fresh1", now)
	s2.recordActive("old2", now.Add(-26*time.Hour))

	pruned := w.PruneActiveMsgs(now.Add(-25 * time.Hour))
	if pruned != 2 {
		t.Errorf("pruned = %d, want 2", pruned)
	}
	if _, ok := s1.activeMsgs["old1"]; ok {
		t.Errorf("old1 should be pruned")
	}
	if _, ok := s1.activeMsgs["fresh1"]; !ok {
		t.Errorf("fresh1 should remain")
	}
	if _, ok := s2.activeMsgs["old2"]; ok {
		t.Errorf("old2 should be pruned")
	}
}

func TestPerIPWindow_DistinctScriptCount(t *testing.T) {
	w := newPerIPWindow(64)
	now := time.Now()
	w.append("192.0.2.1", "scriptA", now)
	w.append("192.0.2.1", "scriptB", now)
	w.append("192.0.2.1", "scriptA", now) // duplicate; still 2 distinct
	w.append("192.0.2.2", "scriptC", now)

	n := w.distinctScriptsSince("192.0.2.1", now.Add(-time.Hour))
	if n != 2 {
		t.Errorf("distinctScriptsSince = %d, want 2", n)
	}
}

func TestPerIPWindow_SweepIdle(t *testing.T) {
	w := newPerIPWindow(64)
	w.append("192.0.2.1", "s", time.Now().Add(-2*time.Hour))
	w.append("192.0.2.2", "s", time.Now())
	n := w.SweepIdle(time.Now().Add(-time.Hour))
	if n != 1 {
		t.Errorf("SweepIdle dropped = %d, want 1", n)
	}
}
