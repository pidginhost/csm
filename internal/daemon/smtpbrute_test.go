package daemon

import (
	"testing"
	"time"
)

// staticClock returns a configurable fixed time.
type staticClock struct{ t time.Time }

func (c *staticClock) Now() time.Time          { return c.t }
func (c *staticClock) advance(d time.Duration) { c.t = c.t.Add(d) }

func newTestTracker(t *testing.T, clock *staticClock) *smtpAuthTracker {
	t.Helper()
	return newSMTPAuthTracker(
		5,              // perIPThreshold
		8,              // subnetThreshold
		12,             // accountSprayThreshold
		10*time.Minute, // window
		60*time.Minute, // suppression
		20000,          // maxTracked
		clock.Now,
	)
}

func TestSMTPAuthTracker_InitialSizeIsZero(t *testing.T) {
	clock := &staticClock{t: time.Date(2026, 4, 14, 12, 0, 0, 0, time.UTC)}
	tr := newTestTracker(t, clock)
	if got := tr.Size(); got != 0 {
		t.Errorf("Size() = %d, want 0", got)
	}
}
