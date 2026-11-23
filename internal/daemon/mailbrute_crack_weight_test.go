package daemon

import (
	"fmt"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

// A crack after at least the per-address brute-force threshold of failures on
// its mailbox is marked as guessed, across spellings of the address; fewer
// failures look like an owner mistyping.
func TestMailCrackMarksBruteForce(t *testing.T) {
	for _, tc := range []struct {
		name     string
		spelling []string
		want     bool
	}{
		{"two failures", []string{"198.51.100.20", "198.51.100.20"}, false},
		{"below threshold", []string{"198.51.100.20", "198.51.100.20", "198.51.100.20", "198.51.100.20"}, false},
		{"at threshold", []string{"198.51.100.20", "198.51.100.20", "198.51.100.20", "198.51.100.20", "198.51.100.20"}, true},
		{"spellings combined", []string{"198.51.100.20", "198.51.100.20", "198.51.100.20", "::ffff:198.51.100.20", "::ffff:198.51.100.20"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			clock := &staticClock{t: time.Now().UTC().Truncate(time.Second)}
			tr := newTestMailTracker(t, clock)
			for _, ip := range tc.spelling {
				tr.Record(ip, "user@example.com")
				clock.advance(time.Second)
			}
			f := findCheck(tr.recordSuccessAt("198.51.100.20", "user@example.com", clock.Now(), knownCustomerIMAP, true), "mail_account_compromised")
			if f == nil || f.Severity != alert.Critical || f.BruteForced != tc.want {
				t.Fatalf("crack = %s, want Critical with BruteForced %v", fmt.Sprint(f), tc.want)
			}
		})
	}
}

func TestMailBruteCrackSurvivesSprayVerdict(t *testing.T) {
	for _, account := range []string{"real@victim.example", "cpuser"} {
		t.Run(account, func(t *testing.T) {
			clock := &staticClock{t: time.Now().UTC().Truncate(time.Second)}
			tr := newTestMailTracker(t, clock)
			spray := newMailSpray(sprayConfig{
				Mode: sprayEnforce, Window: 7 * 24 * time.Hour, TrustAge: 10 * time.Minute,
				Suppression: time.Hour, MaxIPs: 20000, MissingNetworks: 2, BlockTTL: time.Hour,
			}, clock.Now)
			tr.SetSpray(spray)
			spray.Failure("192.0.2.1", "missing@victim.example", mailboxMissing)
			spray.Failure("203.0.113.7", "missing@victim.example", mailboxMissing)
			for i := 0; i < tr.perIPThreshold; i++ {
				tr.Record("203.0.113.7", account)
			}
			f := onlyCheck(t, tr.RecordSuccess("203.0.113.7", account), "mail_account_compromised")
			if f.Severity != alert.Critical || f.BlockTTL != time.Hour || !f.BruteForced || f.Mailbox != account {
				t.Fatalf("spray verdict lost the guessed login: %+v", f)
			}
		})
	}
}

func TestMailBruteCrackEscalatesDuringQuietPeriod(t *testing.T) {
	for _, trusted := range []bool{true, false} {
		t.Run(fmt.Sprint(trusted), func(t *testing.T) {
			clock := &staticClock{t: time.Now().UTC().Truncate(time.Second)}
			tr := newTestMailTracker(t, clock)
			const ip, account = "203.0.113.7", "real@victim.example"
			for i := 0; i < 2; i++ {
				tr.Record(ip, account)
			}
			first := onlyCheck(t, tr.recordSuccessAt(ip, account, clock.Now(), knownCustomerIMAP, trusted), "mail_account_compromised")
			if first.BruteForced {
				t.Fatal("two failures marked as brute force")
			}
			for i := 2; i < tr.perIPThreshold; i++ {
				tr.Record(ip, account)
			}
			second := onlyCheck(t, tr.recordSuccessAt(ip, account, clock.Now(), knownCustomerIMAP, trusted), "mail_account_compromised")
			if !second.BruteForced || second.Severity != alert.Critical {
				t.Fatalf("escalation = %+v", second)
			}
			if got := tr.recordSuccessAt(ip, account, clock.Now(), knownCustomerIMAP, trusted); len(got) != 0 {
				t.Fatalf("duplicate escalation = %+v", got)
			}
		})
	}
}

func TestMailBruteCrackCountsOtherAddressSpelling(t *testing.T) {
	for _, failures := range []int{0, 1} {
		t.Run(fmt.Sprint(failures), func(t *testing.T) {
			clock := &staticClock{t: time.Now().UTC().Truncate(time.Second)}
			tr := newTestMailTracker(t, clock)
			for i := 0; i < tr.perIPThreshold-failures; i++ {
				tr.Record("::ffff:198.51.100.20", "user@example.com")
			}
			for i := 0; i < failures; i++ {
				tr.Record("198.51.100.20", "user@example.com")
			}
			f := onlyCheck(t, tr.RecordSuccess("198.51.100.20", "user@example.com"), "mail_account_compromised")
			if !f.BruteForced || f.Severity != alert.Critical {
				t.Fatalf("alias failures lost: %+v", f)
			}
		})
	}
}

func TestMailBruteCrackAliasWindowAndLegitimateHistory(t *testing.T) {
	for _, mode := range []string{"expired", "other mailbox", "success dominant", "established"} {
		t.Run(mode, func(t *testing.T) {
			clock := &staticClock{t: time.Now().UTC().Truncate(time.Second)}
			tr := newTestMailTracker(t, clock)
			const alias, ip, mailbox = "::ffff:198.51.100.20", "198.51.100.20", "user@example.com"
			if mode == "success dominant" || mode == "established" {
				for i := 0; i < tr.perIPThreshold; i++ {
					tr.RecordSuccess(alias, mailbox)
				}
				if mode == "established" {
					clock.advance(tr.window + time.Second)
				}
			}
			account := mailbox
			if mode == "other mailbox" {
				account = "other@example.com"
			}
			for i := 0; i < tr.perIPThreshold; i++ {
				tr.Record(alias, account)
			}
			if mode == "expired" {
				clock.advance(tr.window + time.Second)
			}
			if got := tr.RecordSuccess(ip, mailbox); len(got) != 0 {
				t.Fatalf("%s history caused a crack: %+v", mode, got)
			}
		})
	}
}

func TestMailBruteCrackQuietsLaterWeakCrack(t *testing.T) {
	clock := &staticClock{t: time.Now().UTC().Truncate(time.Second)}
	tr := newTestMailTracker(t, clock)
	const mailbox = "user@example.com"
	for i := 0; i < tr.perIPThreshold; i++ {
		tr.Record("198.51.100.20", mailbox)
	}
	onlyCheck(t, tr.RecordSuccess("198.51.100.20", mailbox), "mail_account_compromised")
	for i := 0; i < 2; i++ {
		tr.Record("198.51.100.21", mailbox)
	}
	if got := tr.RecordSuccess("198.51.100.21", mailbox); len(got) != 0 {
		t.Fatalf("weaker crack repeated an existing alert: %+v", got)
	}
}
