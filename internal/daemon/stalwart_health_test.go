package daemon

import (
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/stalwartlog"
)

func newHealthState(t *testing.T, start time.Time) *stalwartState {
	t.Helper()
	ports, err := stalwartlog.ParsePorts(nil)
	if err != nil {
		t.Fatal(err)
	}
	return newStalwartState(ports, start)
}

func TestStalwartHealthUnparsed(t *testing.T) {
	s := newHealthState(t, stalwartTestStart)
	s.stats.read.Add(60)
	got := s.health(stalwartTestStart.Add(5*time.Minute), true)
	if len(got) != 1 || got[0].Check != "stalwart_log_degraded" || !strings.Contains(got[0].Message, "none in the expected format") {
		t.Fatalf("findings = %+v, want the unparsed finding", got)
	}
	if got[0].DedupKey != "stalwart_log_degraded:unparsed" {
		t.Fatalf("dedup key = %q", got[0].DedupKey)
	}
}

func TestStalwartHealthQuietIsFine(t *testing.T) {
	s := newHealthState(t, stalwartTestStart)
	s.stats.read.Add(10)
	if got := s.health(stalwartTestStart.Add(5*time.Minute), true); len(got) != 0 {
		t.Fatalf("10 unparsed lines alerted: %+v", got)
	}
	s.stats.read.Add(100)
	s.stats.parsed.Add(1)
	if got := s.health(stalwartTestStart.Add(10*time.Minute), true); len(got) != 0 {
		t.Fatalf("an hour with a parsed line alerted: %+v", got)
	}
}

func TestStalwartHealthUnparsedWindowSlides(t *testing.T) {
	s := newHealthState(t, stalwartTestStart)
	s.stats.read.Add(60)
	s.stats.parsed.Add(60)
	s.health(stalwartTestStart.Add(5*time.Minute), true)
	at := stalwartTestStart.Add(5 * time.Minute)
	for i := 0; i < 12; i++ {
		at = at.Add(5 * time.Minute)
		s.stats.read.Add(10)
		got := s.health(at, true)
		if i < 11 && len(got) != 0 {
			t.Fatalf("tick %d: alerted while the hour still held parsed lines: %+v", i, got)
		}
		if i == 11 && len(got) != 1 {
			t.Fatalf("an hour of 120 unparsed lines did not alert: %+v", got)
		}
	}
}

func TestStalwartHealthStalled(t *testing.T) {
	s := newHealthState(t, stalwartTestStart)
	got := s.health(stalwartTestStart.Add(7*time.Hour), true)
	if len(got) != 1 || !strings.Contains(got[0].Message, "has not grown for 6 hours") || got[0].DedupKey != "stalwart_log_degraded:stalled" {
		t.Fatalf("findings = %+v, want the stalled finding", got)
	}
	s = newHealthState(t, stalwartTestStart)
	if got := s.health(stalwartTestStart.Add(7*time.Hour), false); len(got) != 0 {
		t.Fatalf("a stopped service alerted: %+v", got)
	}
	s = newHealthState(t, stalwartTestStart)
	if got := s.health(stalwartTestStart.Add(5*time.Hour), true); len(got) != 0 {
		t.Fatalf("5 quiet hours alerted: %+v", got)
	}
}

// A burst of SMTP sends with no login to name their sender, as when a flood
// of logins evicts the connections CSM remembers, is reported rather than
// passing unseen.
func TestStalwartHealthUnattributedSends(t *testing.T) {
	s := newHealthState(t, stalwartTestStart)
	s.stats.read.Add(100)
	s.stats.parsed.Add(100)
	s.stats.unattributed.Add(19)
	if got := s.health(stalwartTestStart.Add(5*time.Minute), true); len(got) != 0 {
		t.Fatalf("19 unattributed sends alerted: %+v", got)
	}
	s.stats.unattributed.Add(1)
	got := s.health(stalwartTestStart.Add(10*time.Minute), true)
	if len(got) != 1 || got[0].DedupKey != "stalwart_log_degraded:unattributed" || !strings.Contains(got[0].Message, "20 authenticated SMTP sends") {
		t.Fatalf("findings = %+v, want the unattributed finding", got)
	}
}
