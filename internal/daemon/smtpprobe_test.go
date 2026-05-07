package daemon

import (
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

func newTestProbeTracker(t *testing.T, clock *staticClock) *smtpProbeTracker {
	t.Helper()
	return newSMTPProbeTracker(
		100,           // threshold
		5*time.Minute, // window
		60*time.Minute,
		20000, // maxTracked
		clock.Now,
		nil, // expiryStrFn
	)
}

func TestSMTPProbeTracker_InitialSizeIsZero(t *testing.T) {
	clock := &staticClock{t: time.Date(2026, 5, 6, 12, 0, 0, 0, time.UTC)}
	tr := newTestProbeTracker(t, clock)
	if got := tr.Size(); got != 0 {
		t.Errorf("Size() = %d, want 0", got)
	}
}

func TestSMTPProbeTracker_NoFindingBelowThreshold(t *testing.T) {
	clock := &staticClock{t: time.Date(2026, 5, 6, 12, 0, 0, 0, time.UTC)}
	tr := newTestProbeTracker(t, clock)
	for i := 0; i < 99; i++ {
		if got := tr.Record("203.0.113.5"); got != nil {
			t.Fatalf("record %d under threshold: got finding, want nil", i)
		}
	}
}

func TestSMTPProbeTracker_FiresAtThresholdWithExpectedShape(t *testing.T) {
	clock := &staticClock{t: time.Date(2026, 5, 6, 12, 0, 0, 0, time.UTC)}
	tr := newTestProbeTracker(t, clock)

	var last []alert.Finding
	for i := 0; i < 100; i++ {
		last = tr.Record("203.0.113.5")
	}
	if len(last) == 0 {
		t.Fatalf("expected finding at 100th record, got none")
	}
	f := last[0]
	if f.Check != "smtp_probe_abuse" {
		t.Errorf("Check = %q, want smtp_probe_abuse", f.Check)
	}
	if f.Severity != alert.High {
		t.Errorf("Severity = %v, want alert.High", f.Severity)
	}
	if !strings.Contains(f.Message, "203.0.113.5") {
		t.Errorf("Message %q must include the source IP", f.Message)
	}
	if !strings.Contains(f.Message, "100") {
		t.Errorf("Message %q must include the connection count", f.Message)
	}
}

// When the daemon supplies a live block-expiry string (i.e. auto-response is
// enabled with block_ips), the finding's Details must tell the operator the
// source IP is auto-blocked and for how long, instead of advising "consider
// auto-block" which contradicts the runtime behaviour.
func TestSMTPProbeTracker_DetailsIncludesConfiguredExpiry(t *testing.T) {
	clock := &staticClock{t: time.Date(2026, 5, 6, 12, 0, 0, 0, time.UTC)}
	tr := newSMTPProbeTracker(
		100,
		5*time.Minute,
		60*time.Minute,
		20000,
		clock.Now,
		func() string { return "12h" },
	)

	var last []alert.Finding
	for i := 0; i < 100; i++ {
		last = tr.Record("203.0.113.5")
	}
	if len(last) == 0 {
		t.Fatalf("expected finding at 100th record, got none")
	}
	d := last[0].Details
	if !strings.Contains(d, "scheduled for auto-block (12h)") {
		t.Errorf("Details = %q, want phrase \"scheduled for auto-block (12h)\"", d)
	}
	if strings.Contains(d, "consider manual block") {
		t.Errorf("Details = %q, must not still advise \"consider manual block\" when expiry is supplied", d)
	}
}

// When auto-response is disabled (or block_ips is off), the daemon supplies an
// empty expiry string. The Details should fall back to advising manual review,
// not claim a block that did not happen.
func TestSMTPProbeTracker_DetailsFallbackWhenAutoBlockDisabled(t *testing.T) {
	clock := &staticClock{t: time.Date(2026, 5, 6, 12, 0, 0, 0, time.UTC)}
	tr := newSMTPProbeTracker(
		100,
		5*time.Minute,
		60*time.Minute,
		20000,
		clock.Now,
		func() string { return "" },
	)

	var last []alert.Finding
	for i := 0; i < 100; i++ {
		last = tr.Record("203.0.113.5")
	}
	if len(last) == 0 {
		t.Fatalf("expected finding at 100th record, got none")
	}
	d := last[0].Details
	if !strings.Contains(d, "consider manual block") {
		t.Errorf("Details = %q, want fallback advising \"consider manual block\"", d)
	}
	if strings.Contains(d, "scheduled for auto-block") {
		t.Errorf("Details = %q, must not claim auto-block scheduled when expiry function returned empty", d)
	}
}

// A scanner that keeps probing should not generate one finding per connection
// after the threshold trips; that would alert-storm the operator. The
// tracker must suppress repeats for the configured suppression window.
func TestSMTPProbeTracker_SuppressesRepeatsWithinWindow(t *testing.T) {
	clock := &staticClock{t: time.Date(2026, 5, 6, 12, 0, 0, 0, time.UTC)}
	tr := newTestProbeTracker(t, clock)

	for i := 0; i < 100; i++ {
		tr.Record("203.0.113.5") // trips at 100
	}
	for i := 0; i < 50; i++ {
		if got := tr.Record("203.0.113.5"); got != nil {
			t.Fatalf("record %d after first finding inside suppression window: got finding, want nil", i)
		}
	}
}

// After suppression elapses, a continuing flood should re-fire so the
// operator is notified that the abuse persisted.
func TestSMTPProbeTracker_RefiresAfterSuppressionWindow(t *testing.T) {
	clock := &staticClock{t: time.Date(2026, 5, 6, 12, 0, 0, 0, time.UTC)}
	tr := newTestProbeTracker(t, clock)

	for i := 0; i < 100; i++ {
		tr.Record("203.0.113.5") // first finding
	}
	clock.advance(61 * time.Minute) // past 60-min suppression
	for i := 0; i < 99; i++ {
		tr.Record("203.0.113.5")
	}
	last := tr.Record("203.0.113.5") // 100th in fresh window
	if len(last) == 0 {
		t.Fatalf("expected finding on 100th post-suppression record, got none")
	}
}

// Stale connections outside the rolling window must not count. A user who
// makes 60 connections, waits 6 minutes, and makes 60 more should not trip
// a 5-min/100-connection threshold.
func TestSMTPProbeTracker_PrunesOldConnectionsBeyondWindow(t *testing.T) {
	clock := &staticClock{t: time.Date(2026, 5, 6, 12, 0, 0, 0, time.UTC)}
	tr := newTestProbeTracker(t, clock)

	for i := 0; i < 60; i++ {
		tr.Record("203.0.113.5")
	}
	clock.advance(6 * time.Minute) // past 5-min window
	for i := 0; i < 60; i++ {
		if got := tr.Record("203.0.113.5"); got != nil {
			t.Fatalf("record %d after window slide: spurious finding %+v", i, got)
		}
	}
}

func TestSMTPProbeTracker_TracksDistinctIPsSeparately(t *testing.T) {
	clock := &staticClock{t: time.Date(2026, 5, 6, 12, 0, 0, 0, time.UTC)}
	tr := newTestProbeTracker(t, clock)

	for i := 0; i < 99; i++ {
		tr.Record("203.0.113.5")
	}
	if got := tr.Record("198.51.100.7"); got != nil {
		t.Fatalf("first record from new IP must not fire: got %+v", got)
	}
	last := tr.Record("203.0.113.5") // 100th from first IP
	if len(last) == 0 {
		t.Fatalf("threshold IP must still fire after unrelated IP records")
	}
}

func TestSMTPProbeTracker_IgnoresEmptyIP(t *testing.T) {
	clock := &staticClock{t: time.Date(2026, 5, 6, 12, 0, 0, 0, time.UTC)}
	tr := newTestProbeTracker(t, clock)
	if got := tr.Record(""); got != nil {
		t.Errorf("empty IP must not record, got %+v", got)
	}
	if tr.Size() != 0 {
		t.Errorf("Size after empty IP = %d, want 0", tr.Size())
	}
}

// parseEximConnectionLine should extract the source IP from log lines like
//
//	2026-05-06 16:44:42 SMTP connection from (localhost) [203.0.113.33]:43018 lost D=5s
//	2026-05-06 17:05:43 SMTP connection from [198.51.100.92]:65417 (TCP/IP connection count = 7)
//
// and ignore lines that aren't SMTP connection events (queue runs, deliveries,
// authenticator failures, etc.) so the probe tracker only sees connect events.
func TestParseEximSMTPConnectIP(t *testing.T) {
	tests := []struct {
		name string
		line string
		want string
	}{
		{
			"plain connect with TCP count",
			`2026-05-06 17:05:43 SMTP connection from [198.51.100.92]:65417 (TCP/IP connection count = 7)`,
			"198.51.100.92",
		},
		{
			"connect with HELO and lost",
			`2026-05-06 16:44:42 SMTP connection from (localhost) [203.0.113.33]:43018 lost D=5s`,
			"203.0.113.33",
		},
		{
			"connect with bracketed HELO and lost",
			`2026-05-06 16:44:51 SMTP connection from ([198.51.100.133]) [203.0.113.44]:38294 lost D=15s`,
			"203.0.113.44",
		},
		{
			"connect closed by quit",
			`2026-05-06 11:34:19 SMTP connection from ([192.0.2.94]) [198.51.100.92]:64547 D=5s closed by QUIT`,
			"198.51.100.92",
		},
		{"queue line", `2026-05-06 11:34:14 1wKXhu-00000001j9B-2oEv <= info@example.test H=([192.0.2.94]) [198.51.100.92]:64547 P=esmtpsa`, ""},
		{"empty", "", ""},
		{"different log type", `2026-05-06 01:03:27 1wKNrT-0000000EfsC-45eC malware acl condition: clamd /var/clamd : unable to connect`, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := parseEximSMTPConnectIP(tc.line); got != tc.want {
				t.Errorf("parseEximSMTPConnectIP(%q) = %q, want %q", tc.line, got, tc.want)
			}
		})
	}
}
