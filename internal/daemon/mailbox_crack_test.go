package daemon

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

// A crack, a login after failed logins, is one sign in the mailbox's
// evidence ledger. Alone it never suspends: an owner who mistypes a password
// twice produces the same pattern.
func TestCrackAloneRecordsEvidence(t *testing.T) {
	db, calls := evidenceCase(t)
	if got := stolenLoginResponses(eximAutoHoldConfig(), []alert.Finding{stolenLogin("real@victim.example", alert.Critical)}); len(got) != 0 {
		t.Fatalf("findings = %+v; a crack alone must not reach an incident", got)
	}
	if len(*calls) != 0 {
		t.Fatalf("uapi calls = %v; a crack alone suspended the mailbox", *calls)
	}
	e, err := db.GetMailboxEvidence("real@victim.example")
	if err != nil || len(e.Signals) != 1 || e.Signals[0].Kind != signalCrack || mailboxEvidenceScore(e) != 2 {
		t.Fatalf("evidence = %+v (err %v), want one crack sign worth 2", e, err)
	}
}

// With one more sign the evidence incident suspends the mailbox, whichever
// sign comes first.
func TestCrackWithAnotherSignSuspends(t *testing.T) {
	for _, crackFirst := range []bool{true, false} {
		t.Run(fmt.Sprint("crack first ", crackFirst), func(t *testing.T) {
			db, calls := evidenceCase(t)
			cfg := eximAutoHoldConfig()
			crack := func() []alert.Finding {
				return stolenLoginResponses(cfg, []alert.Finding{stolenLogin("real@victim.example", alert.Critical)})
			}
			country := func() []alert.Finding {
				return observeMailboxSignal(cfg, "real@victim.example", newCountry("RU", time.Now()))
			}
			first, second := country, crack
			if crackFirst {
				first, second = crack, country
			}
			if got := first(); len(got) != 0 {
				t.Fatalf("the first sign reported %+v", got)
			}
			f := onlyIncident(t, second())
			if !strings.HasPrefix(f.Message, "Suspended mailbox real@victim.example") || !strings.Contains(f.Message, "scored 4") ||
				!strings.Contains(f.Details, "login from 203.0.113.7 after failed logins") {
				t.Fatalf("incident = %+v", f)
			}
			if !reflect.DeepEqual(*calls, [][]string{uapiArgs("suspend_login"), uapiArgs("suspend_outgoing")}) {
				t.Fatalf("uapi calls = %v", *calls)
			}
			if row := onlySuspension(t, db); row.Check != "email_mailbox_compromise" {
				t.Fatalf("row = %+v", row)
			}
		})
	}
}

// A crack withdraws the mailbox's login standing when its finding is handled,
// whoever raised it: the address that cracked it may have earned standing.
func TestCrackRevokesMailboxStanding(t *testing.T) {
	evidenceCase(t)
	clock := &staticClock{t: standingBase}
	s := newLoginStanding(clock.Now)
	earnStanding(t, s, standingIP, "real@victim.example")
	earnStanding(t, s, standingIP, "other@victim.example")
	withMailboxResponseStanding(t, s)
	stolenLoginResponses(eximAutoHoldConfig(), []alert.Finding{stolenLogin("real@victim.example", alert.Critical)})
	if hasRow(s, standingIP, "real@victim.example") || !hasRow(s, standingIP, "other@victim.example") {
		t.Fatal("the crack did not withdraw exactly the cracked mailbox's standing")
	}
}
