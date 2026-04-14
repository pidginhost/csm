package daemon

import (
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
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

func TestSMTPAuthTracker_NoFindingBelowPerIPThreshold(t *testing.T) {
	clock := &staticClock{t: time.Date(2026, 4, 14, 12, 0, 0, 0, time.UTC)}
	tr := newTestTracker(t, clock)
	for i := 0; i < 4; i++ {
		if got := tr.Record("203.0.113.5", ""); got != nil {
			t.Fatalf("record %d: got %v, want nil", i, got)
		}
	}
}

func TestSMTPAuthTracker_EmitsSMTPBruteForceAtThreshold(t *testing.T) {
	clock := &staticClock{t: time.Date(2026, 4, 14, 12, 0, 0, 0, time.UTC)}
	tr := newTestTracker(t, clock)
	var last []alert.Finding
	for i := 0; i < 5; i++ {
		last = tr.Record("203.0.113.5", "")
	}
	if len(last) == 0 {
		t.Fatalf("expected finding on 5th record, got nil")
	}
	var f *alert.Finding
	for i := range last {
		if last[i].Check == "smtp_bruteforce" {
			f = &last[i]
			break
		}
	}
	if f == nil {
		t.Fatalf("no smtp_bruteforce finding in %v", last)
	}
	if f.Severity != alert.Critical {
		t.Errorf("severity = %v, want Critical", f.Severity)
	}
	if !strings.Contains(f.Message, "203.0.113.5") {
		t.Errorf("message %q does not contain IP", f.Message)
	}
	if !strings.Contains(f.Message, " from ") {
		t.Errorf("message %q does not use ' from ' separator required by extractIPFromFinding", f.Message)
	}
}

func TestSMTPAuthTracker_NoDuplicatePerIPFindingsInSuppressionWindow(t *testing.T) {
	clock := &staticClock{t: time.Date(2026, 4, 14, 12, 0, 0, 0, time.UTC)}
	tr := newTestTracker(t, clock)
	for i := 0; i < 5; i++ {
		tr.Record("203.0.113.5", "")
	}
	for i := 0; i < 10; i++ {
		clock.advance(1 * time.Second)
		out := tr.Record("203.0.113.5", "")
		for _, f := range out {
			if f.Check == "smtp_bruteforce" {
				t.Fatalf("duplicate smtp_bruteforce finding during suppression at iteration %d", i)
			}
		}
	}
}

func TestSMTPAuthTracker_SuppressionExpires_ReFires(t *testing.T) {
	clock := &staticClock{t: time.Date(2026, 4, 14, 12, 0, 0, 0, time.UTC)}
	tr := newTestTracker(t, clock)
	for i := 0; i < 5; i++ {
		tr.Record("203.0.113.5", "")
	}
	// Advance past suppression AND past window — counter must be fresh.
	clock.advance(61 * time.Minute)
	var fired bool
	for i := 0; i < 5; i++ {
		for _, f := range tr.Record("203.0.113.5", "") {
			if f.Check == "smtp_bruteforce" {
				fired = true
			}
		}
	}
	if !fired {
		t.Fatalf("expected re-fire after suppression window")
	}
}

func TestSMTPAuthTracker_WindowExpiryResetsCount(t *testing.T) {
	clock := &staticClock{t: time.Date(2026, 4, 14, 12, 0, 0, 0, time.UTC)}
	tr := newTestTracker(t, clock)
	for i := 0; i < 4; i++ {
		tr.Record("203.0.113.5", "")
	}
	// Window is 10 min; advance 11 min so prior 4 timestamps fall out.
	clock.advance(11 * time.Minute)
	for i := 0; i < 4; i++ {
		if out := tr.Record("203.0.113.5", ""); len(out) != 0 {
			t.Fatalf("unexpected finding after window reset: %v", out)
		}
	}
}

func TestSMTPAuthTracker_MultipleIPsIndependent(t *testing.T) {
	clock := &staticClock{t: time.Date(2026, 4, 14, 12, 0, 0, 0, time.UTC)}
	tr := newTestTracker(t, clock)
	for i := 0; i < 4; i++ {
		tr.Record("203.0.113.5", "")
		tr.Record("198.51.100.7", "")
	}
	if got := tr.Record("203.0.113.5", ""); len(got) == 0 {
		t.Errorf("203.0.113.5 should fire at 5th record")
	}
	if got := tr.Record("198.51.100.7", ""); len(got) == 0 {
		t.Errorf("198.51.100.7 should fire at 5th record independently")
	}
}

func TestSMTPAuthTracker_EmptyIPIgnored(t *testing.T) {
	clock := &staticClock{t: time.Date(2026, 4, 14, 12, 0, 0, 0, time.UTC)}
	tr := newTestTracker(t, clock)
	for i := 0; i < 20; i++ {
		if out := tr.Record("", ""); out != nil {
			t.Fatalf("empty IP must return nil, got %v", out)
		}
	}
	if tr.Size() != 0 {
		t.Errorf("Size() = %d, want 0 for empty-IP-only input", tr.Size())
	}
}
