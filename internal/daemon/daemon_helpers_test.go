package daemon

import (
	"testing"
	"time"
)

// parseBlockExpiry tests are in coverage_test.go.

func TestParseBlockExpiryDays(t *testing.T) {
	d := parseBlockExpiry("48h")
	if d != 48*time.Hour {
		t.Errorf("got %v, want 48h", d)
	}
}

// --- truncateStr -----------------------------------------------------

func TestTruncateStrShort(t *testing.T) {
	if got := truncateStr("hello", 10); got != "hello" {
		t.Errorf("got %q", got)
	}
}

func TestTruncateStrLong(t *testing.T) {
	got := truncateStr("hello world this is long", 10)
	if len(got) > 13 { // 10 + "..."
		t.Errorf("should be truncated, got %q (len %d)", got, len(got))
	}
}

// --- filterUnsuppressedFindings already tested, but exercise more -----

// filterUnsuppressed nil test is in coverage_test.go.

// --- DroppedAlerts ---------------------------------------------------

func TestDroppedAlertsZero(t *testing.T) {
	d := &Daemon{}
	if d.DroppedAlerts() != 0 {
		t.Errorf("new daemon should have 0 dropped alerts")
	}
}
