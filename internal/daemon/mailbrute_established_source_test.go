package daemon

import (
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

// establishOfficeStanding gives ip established good standing on the given
// mailboxes: first success older than the failure window, latest success
// still within the good-source TTL.
func establishOfficeStanding(tr *mailAuthTracker, clock *staticClock, ip string, accounts ...string) {
	for _, a := range accounts {
		tr.RecordSuccess(ip, a)
	}
	clock.t = clock.t.Add(11 * time.Minute)
	for _, a := range accounts {
		tr.RecordSuccess(ip, a)
	}
}

func compromiseFinding(out []alert.Finding) *alert.Finding {
	for i := range out {
		if out[i].Check == "mail_account_compromised" {
			return &out[i]
		}
	}
	return nil
}

func TestMailAuthTracker_CompromiseDowngradedForEstablishedMultiMailboxSource(t *testing.T) {
	clock := &staticClock{t: time.Date(2026, 4, 14, 12, 0, 0, 0, time.UTC)}
	tr := newTestMailTracker(t, clock)
	ip := "203.0.113.5"
	establishOfficeStanding(tr, clock, ip, "office1@example.com", "office2@example.com")

	tr.Record(ip, "victim@example.com")
	tr.Record(ip, "victim@example.com")
	f := compromiseFinding(tr.RecordSuccess(ip, "victim@example.com"))
	if f == nil {
		t.Fatal("compromise finding must still be emitted for visibility")
	}
	if f.Severity != alert.High {
		t.Fatalf("severity = %v, want High for an established multi-mailbox source", f.Severity)
	}
	if !strings.Contains(f.Details, "2 other mailboxes") {
		t.Fatalf("details %q missing established-source annotation", f.Details)
	}
}

func TestMailAuthTracker_CompromiseStaysCriticalWithSingleEstablishedAccount(t *testing.T) {
	clock := &staticClock{t: time.Date(2026, 4, 14, 12, 0, 0, 0, time.UTC)}
	tr := newTestMailTracker(t, clock)
	ip := "203.0.113.5"
	establishOfficeStanding(tr, clock, ip, "office1@example.com")

	tr.Record(ip, "victim@example.com")
	tr.Record(ip, "victim@example.com")
	f := compromiseFinding(tr.RecordSuccess(ip, "victim@example.com"))
	if f == nil {
		t.Fatal("compromise finding missing")
	}
	if f.Severity != alert.Critical {
		t.Fatalf("severity = %v, want Critical: one prior mailbox is not an office pattern", f.Severity)
	}
}

func TestMailAuthTracker_CompromiseStaysCriticalWhenOtherSuccessesAreFresh(t *testing.T) {
	clock := &staticClock{t: time.Date(2026, 4, 14, 12, 0, 0, 0, time.UTC)}
	tr := newTestMailTracker(t, clock)
	ip := "203.0.113.5"
	// Same-window padding successes on other mailboxes must earn nothing:
	// a stuffing run that lands two mailboxes cannot vouch for the third.
	tr.RecordSuccess(ip, "loot1@example.com")
	tr.RecordSuccess(ip, "loot2@example.com")

	tr.Record(ip, "victim@example.com")
	tr.Record(ip, "victim@example.com")
	f := compromiseFinding(tr.RecordSuccess(ip, "victim@example.com"))
	if f == nil {
		t.Fatal("compromise finding missing")
	}
	if f.Severity != alert.Critical {
		t.Fatalf("severity = %v, want Critical: fresh successes are not established standing", f.Severity)
	}
}

func TestMailAuthTracker_CompromiseStaysCriticalWhenOtherStandingIsStale(t *testing.T) {
	clock := &staticClock{t: time.Date(2026, 4, 14, 12, 0, 0, 0, time.UTC)}
	tr := newTestMailTracker(t, clock)
	ip := "203.0.113.5"
	establishOfficeStanding(tr, clock, ip, "office1@example.com", "office2@example.com")
	clock.advance(mailGoodSourceTTL + time.Second)

	tr.Record(ip, "victim@example.com")
	tr.Record(ip, "victim@example.com")
	f := compromiseFinding(tr.RecordSuccess(ip, "victim@example.com"))
	if f == nil {
		t.Fatal("compromise finding missing")
	}
	if f.Severity != alert.Critical {
		t.Fatalf("severity = %v, want Critical: stale standing must not vouch for a compromise", f.Severity)
	}
}

func TestMailAuthTracker_DowngradedCompromiseDoesNotTrainGoodSource(t *testing.T) {
	clock := &staticClock{t: time.Date(2026, 4, 14, 12, 0, 0, 0, time.UTC)}
	tr := newTestMailTracker(t, clock)
	ip := "203.0.113.5"
	establishOfficeStanding(tr, clock, ip, "office1@example.com", "office2@example.com")

	tr.Record(ip, "victim@example.com")
	tr.Record(ip, "victim@example.com")
	f := compromiseFinding(tr.RecordSuccess(ip, "victim@example.com"))
	if f == nil || f.Severity != alert.High {
		t.Fatalf("expected downgraded compromise finding, got %+v", f)
	}
	if _, ok := tr.ExportGoodSource()[ip]["victim@example.com"]; ok {
		t.Fatal("a downgraded compromise success must not establish good-source standing")
	}
}
