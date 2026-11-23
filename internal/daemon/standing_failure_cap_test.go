package daemon

import (
	"slices"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

func TestSMTPStandingFailureCapSurvivesReload(t *testing.T) {
	clock := &staticClock{t: standingBase}
	tr, s := newStandingSMTPTracker(t, clock)
	earnStanding(t, s, standingIP, standingBox)
	tr.SetThresholds(5, 8, 12, 10*time.Minute, 0, 0, 0, 20000)
	recordSMTP(tr, standingIP, slices.Repeat([]string{standingBox}, 501)...)
	tr.SetThresholds(50, 8, 12, 10*time.Minute, 0, 0, 0, 20000)
	if f := findCheck(tr.Record(standingIP, standingBox), "smtp_bruteforce"); f == nil {
		t.Fatal("raising the threshold forgot failures still above the new standing cap")
	}
}

func TestStandingFailureCapAcrossAddressAliases(t *testing.T) {
	for _, protocol := range []string{"mail", "smtp"} {
		t.Run(protocol, func(t *testing.T) {
			clock := &staticClock{t: standingBase}
			var record func(string, string) []alert.Finding
			var s *loginStanding
			if protocol == "mail" {
				tr, standing := newStandingMailTracker(t, clock)
				record, s = tr.Record, standing
			} else {
				tr, standing := newStandingSMTPTracker(t, clock)
				record, s = tr.Record, standing
			}
			earnStanding(t, s, standingIP, standingBox)
			for range 26 {
				record(standingIP, standingBox)
			}
			alias := "::ffff:" + standingIP
			for range 24 {
				record(alias, standingBox)
			}
			if f := findCheck(record(alias, standingBox), protocol+"_bruteforce"); f == nil {
				t.Fatal("alternate address spelling bypassed the per-mailbox failure cap")
			}
		})
	}
}

func TestMailStandingCrackCapAcrossAddressAliases(t *testing.T) {
	clock := &staticClock{t: standingBase}
	tr, s := newStandingMailTracker(t, clock)
	earnStanding(t, s, standingIP, standingBox)
	recordMail(tr, standingIP, slices.Repeat([]string{standingBox}, 49)...)
	alias := "::ffff:" + standingIP
	recordMail(tr, alias, standingBox, standingBox)
	if f := findCheck(tr.RecordSuccess(alias, standingBox), "mail_account_compromised"); f == nil || f.Severity != alert.Critical {
		t.Fatalf("over-cap compromise through alias = %+v, want Critical", f)
	}
}

func TestMailStandingCrackEscalatesWithinQuietPeriod(t *testing.T) {
	for _, trusted := range []bool{true, false} {
		name := "trusted"
		if !trusted {
			name = "untrusted"
		}
		t.Run(name, func(t *testing.T) {
			clock := &staticClock{t: standingBase}
			tr, s := newStandingMailTracker(t, clock)
			earnStanding(t, s, standingIP, standingBox)
			recordMail(tr, standingIP, standingBox, standingBox)
			success := func() []alert.Finding {
				return tr.recordSuccessAt(standingIP, standingBox, clock.Now(), knownCustomerIMAP, trusted)
			}
			if f := findCheck(success(), "mail_account_compromised"); f == nil || f.Severity != alert.High {
				t.Fatalf("initial standing compromise = %+v, want High", f)
			}
			if f := findCheck(success(), "mail_account_compromised"); f != nil {
				t.Fatal("repeated advisory ignored its quiet period")
			}
			recordMail(tr, standingIP, slices.Repeat([]string{standingBox}, 49)...)
			if f := findCheck(success(), "mail_account_compromised"); f == nil || f.Severity != alert.Critical {
				t.Fatalf("advisory silenced over-cap compromise: %+v", f)
			}
			if f := findCheck(success(), "mail_account_compromised"); f != nil {
				t.Fatal("repeated critical compromise ignored its quiet period")
			}
		})
	}
}

func TestStandingSlowCapAcrossAddressAliases(t *testing.T) {
	for _, protocol := range []string{"mail", "smtp"} {
		t.Run(protocol, func(t *testing.T) {
			clock := &staticClock{t: standingBase}
			var record func(string, string) []alert.Finding
			var s *loginStanding
			if protocol == "mail" {
				tr, standing := newStandingMailTracker(t, clock)
				record, s = tr.Record, standing
			} else {
				tr, standing := newStandingSMTPTracker(t, clock)
				record, s = tr.Record, standing
			}
			boxes := []string{standingBox, otherBox, "third@example.com"}
			earnStanding(t, s, standingIP, boxes...)
			alias := "::ffff:" + standingIP
			for i := range 40 {
				record(alias, boxes[i%len(boxes)])
				clock.advance(3 * time.Minute)
			}
			for range 51 {
				record(standingIP, standingBox)
			}
			// This alias remains below the fast threshold. Its slow mailbox set
			// must consult the other spelling's recent failures too.
			if f := findCheck(record(alias, otherBox), protocol+"_bruteforce"); f == nil {
				t.Fatal("slow standing ignored over-cap failures under another spelling")
			}
		})
	}
}

func TestStandingCapIsPerMailboxAndExpires(t *testing.T) {
	for _, protocol := range []string{"mail", "smtp"} {
		t.Run(protocol, func(t *testing.T) {
			clock := &staticClock{t: standingBase}
			var record func(string, string) []alert.Finding
			var s *loginStanding
			if protocol == "mail" {
				tr, standing := newStandingMailTracker(t, clock)
				record, s = tr.Record, standing
			} else {
				tr, standing := newStandingSMTPTracker(t, clock)
				record, s = tr.Record, standing
			}
			earnStanding(t, s, standingIP, standingBox, otherBox)
			for range 50 {
				for _, box := range []string{standingBox, otherBox} {
					if f := findCheck(record(standingIP, box), protocol+"_bruteforce"); f != nil {
						t.Fatal("failures on different mailboxes shared a cap")
					}
				}
			}
			if f := findCheck(record(standingIP, standingBox), protocol+"_bruteforce"); f == nil {
				t.Fatal("one mailbox past its cap was not blocked")
			}
			clock.advance(10*time.Minute + time.Nanosecond)
			// No purge: the untouched canonical entry still holds expired times.
			var out []alert.Finding
			for range 5 {
				out = append(out, record("::ffff:"+standingIP, standingBox)...)
			}
			isStandingAdvisory(t, findCheck(out, "mail_bruteforce_suspected"), standingBox)
			if f := findCheck(out, protocol+"_bruteforce"); f != nil {
				t.Fatal("expired failures under another spelling kept standing over cap")
			}
		})
	}
}

func TestSMTPStandingHistoryBoundedAndPruned(t *testing.T) {
	clock := &staticClock{t: standingBase}
	tr, s := newStandingSMTPTracker(t, clock)
	earnStanding(t, s, standingIP, standingBox)
	for i := range 3 * slowBruteMaxTimesPerIP {
		if i%100 == 0 {
			threshold := 2
			if i%200 == 0 {
				threshold = 50
			}
			tr.SetThresholds(threshold, 8, 12, 10*time.Minute, time.Hour, 40, 6*time.Hour, 20000)
		}
		tr.Record(standingIP, standingBox)
		clock.advance(time.Millisecond)
	}
	times := tr.ips[standingIP].fastAccounts[standingBox]
	if len(times) > slowBruteMaxTimesPerIP || len(times) < 501 {
		t.Fatalf("retained %d failures: must be bounded and cover every accepted reload", len(times))
	}
	if !times[len(times)-1].Equal(clock.Now().Add(-time.Millisecond)) {
		t.Fatal("bounded history discarded the newest failure")
	}
	clock.advance(10 * time.Minute)
	tr.Purge()
	e := tr.ips[standingIP]
	if e == nil || len(e.fastAccounts) != 0 || len(e.slowAccounts) != 1 {
		t.Fatalf("purge did not expire fast history while keeping slow evidence: %+v", e)
	}
	failed, _ := tr.episodeFailedOn(standingIP, standingBox)
	if !failed {
		t.Fatal("purge lost the active slow episode")
	}
}
