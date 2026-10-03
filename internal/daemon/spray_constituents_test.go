package daemon

import (
	"fmt"
	"strconv"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/maillog"
)

func constituentObservation(producer string, cursor int, at time.Time) alert.Observation {
	return alert.Observation{Producer: producer, Stream: "f:1:2:e.0", Cursor: strconv.Itoa(cursor), ObservedAt: at}
}

// recordSpray feeds failures from seven addresses, the first one again,
// then an eighth, after one address that leaves the window first. It returns
// the subnet spray finding.
func recordSpray(t *testing.T, clock *staticClock, check string, record func(ip string, obs alert.Observation) []alert.Finding) alert.Finding {
	t.Helper()
	record("203.0.113.200", constituentObservation("p", 1, clock.Now()))
	clock.advance(11 * time.Minute)
	var sprays []alert.Finding
	feed := func(ip string, cursor int) {
		for _, f := range record(ip, constituentObservation("p", cursor, clock.Now())) {
			if f.Check == check {
				sprays = append(sprays, f)
			}
		}
		clock.advance(time.Second)
	}
	for i := 1; i <= 7; i++ {
		feed(fmt.Sprintf("203.0.113.%d", i), 100+i)
	}
	feed("203.0.113.1", 200)
	feed("203.0.113.8", 108)
	if len(sprays) != 1 {
		t.Fatalf("%s findings %+v, want one", check, sprays)
	}
	return sprays[0]
}

func assertConstituents(t *testing.T, spray alert.Finding, start time.Time) {
	t.Helper()
	got := spray.SprayConstituents
	if len(got) != 8 {
		t.Fatalf("constituents %+v, want the eight addresses in the window", got)
	}
	for i, c := range got {
		want := fmt.Sprintf("203.0.113.%d", i+1)
		cursor := 101 + i
		if i == 0 {
			cursor = 200
		}
		if c.Address != want || c.Observation.Cursor != strconv.Itoa(cursor) || c.LastSeen.Before(start) || !c.LastSeen.Equal(c.Observation.ObservedAt) {
			t.Errorf("constituent %d = %+v, want %s named by line %d", i, c, want, cursor)
		}
	}
}

// A subnet spray names each address it counted, with the line that last
// named it; addresses that left the window are not constituents.
func TestMailSubnetSprayNamesItsConstituents(t *testing.T) {
	clock := &staticClock{t: time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)}
	tr := newTestMailTracker(t, clock)
	spray := recordSpray(t, clock, "mail_subnet_spray", func(ip string, obs alert.Observation) []alert.Finding {
		return tr.RecordObserved(ip, "alice@example.com", obs)
	})
	assertConstituents(t, spray, clock.Now().Add(-time.Hour))
}

func TestSMTPSubnetSprayNamesItsConstituents(t *testing.T) {
	clock := &staticClock{t: time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)}
	tr := newTestTracker(t, clock)
	spray := recordSpray(t, clock, "smtp_subnet_spray", func(ip string, obs alert.Observation) []alert.Finding {
		return tr.RecordObserved(ip, "alice@example.com", obs)
	})
	assertConstituents(t, spray, clock.Now().Add(-time.Hour))
}

// The production exim and mail handlers hand each failure line's
// observation to the tracker.
func TestHandlersGiveSprayConstituentsTheirLines(t *testing.T) {
	t.Run("exim", func(t *testing.T) {
		clock := &staticClock{t: time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)}
		d := New(&config.Config{}, nil, nil, "")
		d.smtpAuthTracker = newTestTracker(t, clock)
		spray := recordSpray(t, clock, "smtp_subnet_spray", func(ip string, obs alert.Observation) []alert.Finding {
			return d.handleEximLine(makeEximDovecotFailLine(ip, "alice@example.com"), obs, d.currentCfg())
		})
		assertConstituents(t, spray, clock.Now().Add(-time.Hour))
	})
	t.Run("mail", func(t *testing.T) {
		clock := &staticClock{t: time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)}
		d := New(&config.Config{}, nil, nil, "")
		d.mailAuthTracker = newTestMailTracker(t, clock)
		spray := recordSpray(t, clock, "mail_subnet_spray", func(ip string, obs alert.Observation) []alert.Finding {
			return d.handleMailLine(makeDovecotFailLine("imap", ip, "alice@example.com"), obs, d.currentCfg())
		})
		assertConstituents(t, spray, clock.Now().Add(-time.Hour))
	})
}

// The mail reader gives the handler the line's observation, the same one
// it stamps on the findings.
func TestMailDispatchPassesTheLineObservation(t *testing.T) {
	d := New(&config.Config{}, nil, nil, "")
	at := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	line := maillog.Line{Message: "dovecot: auth failed", Position: maillog.Position{Stream: "m:7:e.0", Cursor: "42", ObservedAt: at}}
	var seen alert.Observation
	if !d.dispatchMailLogLine(line, func(_ string, obs alert.Observation, _ *config.Config) []alert.Finding {
		seen = obs
		return []alert.Finding{{Check: "mail_bruteforce", SourceIP: "192.0.2.90"}}
	}) {
		t.Fatal("dispatch refused")
	}
	got := <-d.alertCh
	want := alert.Observation{Producer: "mail_log", Stream: "m:7:e.0", Cursor: "42", ObservedAt: at}
	if seen != want || got.Observation != want {
		t.Fatalf("handler saw %+v, finding carries %+v, want %+v", seen, got.Observation, want)
	}
}

// A full subnet stays bounded and its finding owns a sorted snapshot.
func TestSprayConstituentsBoundAndSnapshot(t *testing.T) {
	for _, kind := range []string{"mail", "smtp"} {
		t.Run(kind, func(t *testing.T) {
			clock := &staticClock{t: time.Unix(1_700_000_000, 0)}
			var record func(string, string, alert.Observation) []alert.Finding
			if kind == "mail" {
				tr := newTestMailTracker(t, clock)
				tr.subnetThreshold = 256
				record = tr.RecordObserved
			} else {
				tr := newTestTracker(t, clock)
				tr.subnetThreshold = 256
				record = tr.RecordObserved
			}
			var spray alert.Finding
			for i := 255; i >= 0; i-- {
				ip := fmt.Sprintf("203.0.113.%d", i)
				for _, f := range record(ip, "user@example.com", constituentObservation("p", i, clock.Now())) {
					if len(f.SprayConstituents) != 0 {
						spray = f
					}
				}
			}
			if len(spray.SprayConstituents) != 256 {
				t.Fatalf("constituents %d, want all addresses in the subnet", len(spray.SprayConstituents))
			}
			seen := make(map[string]bool)
			for i, c := range spray.SprayConstituents {
				if seen[c.Address] || (i > 0 && spray.SprayConstituents[i-1].Address >= c.Address) {
					t.Fatalf("duplicate or unordered constituent %d: %+v", i, c)
				}
				seen[c.Address] = true
			}
			first := spray.SprayConstituents[0]
			clock.advance(time.Second)
			record(first.Address, "user@example.com", constituentObservation("p", 999, clock.Now()))
			if spray.SprayConstituents[0] != first {
				t.Fatal("later input changed an emitted snapshot")
			}
		})
	}
}
