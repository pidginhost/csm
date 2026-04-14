package daemon

import (
	"testing"
	"time"
)

// staticClock already exists in smtpbrute_test.go — reuse it (same package).
// Do NOT redefine it.

func newTestMailTracker(t *testing.T, clock *staticClock) *mailAuthTracker {
	t.Helper()
	return newMailAuthTracker(
		5,              // perIPThreshold
		8,              // subnetThreshold
		12,             // accountSprayThreshold
		10*time.Minute, // window
		60*time.Minute, // suppression
		20000,          // maxTracked
		clock.Now,
	)
}

func TestMailAuthTracker_InitialSizeIsZero(t *testing.T) {
	clock := &staticClock{t: time.Date(2026, 4, 14, 12, 0, 0, 0, time.UTC)}
	tr := newTestMailTracker(t, clock)
	if got := tr.Size(); got != 0 {
		t.Errorf("Size() = %d, want 0", got)
	}
}
