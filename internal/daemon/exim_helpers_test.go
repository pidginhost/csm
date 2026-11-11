package daemon

import (
	"testing"
	"time"
)

// --- parsePurgeDaemon -------------------------------------------------

func TestParsePurgeDaemonStandard(t *testing.T) {
	line := `[2026-04-12 10:00:00 +0000] info [security] internal PURGE alice:token password_change`
	if got := parsePurgeDaemon(line); got != "alice" {
		t.Errorf("got %q, want alice", got)
	}
}

func TestParsePurgeDaemonNoPurge(t *testing.T) {
	if got := parsePurgeDaemon("no purge here"); got != "" {
		t.Errorf("got %q", got)
	}
}

// --- isDedupExpired ---------------------------------------------------

func TestIsDedupExpiredOldTimestamp(t *testing.T) {
	old := time.Now().Add(-2 * time.Hour).Format(time.RFC3339)
	if !isDedupExpired(old, 1*time.Hour) {
		t.Error("old timestamp should be expired")
	}
}

func TestIsDedupExpiredRecentTimestamp(t *testing.T) {
	recent := time.Now().Format(time.RFC3339)
	if isDedupExpired(recent, 1*time.Hour) {
		t.Error("recent timestamp should not be expired")
	}
}

func TestIsDedupExpiredBadFormat(t *testing.T) {
	if !isDedupExpired("not-a-time", 1*time.Hour) {
		t.Error("bad format should be treated as expired")
	}
}
