package daemon

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/store"
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

// Buffered logins retain their event time so expired or released evidence
// cannot combine with a current sign to suspend the mailbox.
func TestCrackEvidenceUsesLoginTime(t *testing.T) {
	for _, name := range []string{"recent", "expired", "cleared"} {
		t.Run(name, func(t *testing.T) {
			db, calls := evidenceCase(t)
			cfg := eximAutoHoldConfig()
			now := time.Now().UTC().Truncate(time.Second)
			at := now.Add(-2 * time.Hour)
			if name == "expired" {
				at = now.Add(-mailboxEvidenceTTL - time.Hour)
			}
			if name == "cleared" {
				if _, err := db.UpdateMailboxEvidence("real@victim.example", func(e *store.MailboxEvidence) {
					e.ClearedAt = now.Add(-time.Hour)
				}); err != nil {
					t.Fatal(err)
				}
			}
			observeMailboxSignal(cfg, "real@victim.example", newCountry("RU", now))
			tr := newTestMailTracker(t, &staticClock{t: now})
			for i := 0; i < 2; i++ {
				tr.Record("203.0.113.7", "real@victim.example")
			}
			findings := tr.recordSuccessAt("203.0.113.7", "real@victim.example", at, knownCustomerIMAP, true)
			f := onlyCheck(t, findings, "mail_account_compromised")
			if f.Severity != alert.Critical || !f.Timestamp.Equal(at) {
				t.Errorf("crack = %+v, want Critical at the logged time %s", f, at)
			}
			got := stolenLoginResponses(cfg, findings)
			e, err := db.GetMailboxEvidence("real@victim.example")
			if err != nil {
				t.Fatal(err)
			}
			if name != "recent" {
				if len(got) != 0 || len(*calls) != 0 || len(e.Signals) != 1 || e.Signals[0].Kind != signalNewCountry {
					t.Fatalf("old login acted as fresh evidence: findings=%+v calls=%v ledger=%+v", got, *calls, e)
				}
				return
			}
			onlyIncident(t, got)
			if len(*calls) != 2 || len(e.Signals) != 2 || e.Signals[1].Kind != signalCrack ||
				!e.Signals[1].First.Equal(at) || !e.Signals[1].Last.Equal(at) {
				t.Fatalf("recent login lost its time or response: calls=%v ledger=%+v", *calls, e)
			}
		})
	}
}

// A spray verdict can replace the short-window crack or arrive from SMTP.
// Neither source may refresh an expired login when it enters the ledger.
func TestCrackSprayEvidenceUsesLoginTime(t *testing.T) {
	for _, smtp := range []bool{false, true} {
		t.Run(fmt.Sprint("smtp=", smtp), func(t *testing.T) {
			db, calls := evidenceCase(t)
			cfg := eximAutoHoldConfig()
			now := time.Now().UTC().Truncate(time.Second)
			at := now.Add(-mailboxEvidenceTTL - time.Hour)
			clock := &staticClock{t: now}
			spray := newMailSpray(sprayConfig{
				Mode: sprayEnforce, Window: 7 * 24 * time.Hour, TrustAge: 10 * time.Minute,
				Suppression: time.Hour, MaxIPs: 20000, MissingNetworks: 2, BlockTTL: time.Hour,
			}, clock.Now)
			spray.Failure("192.0.2.1", "missing@victim.example", mailboxMissing)
			spray.Failure("203.0.113.7", "missing@victim.example", mailboxMissing)
			var findings []alert.Finding
			if smtp {
				tr := newTestTracker(t, clock)
				tr.SetSpray(spray)
				findings = tr.recordSuccessAt("203.0.113.7", "real@victim.example", at, serviceLog, true)
			} else {
				tr := newTestMailTracker(t, clock)
				tr.SetSpray(spray)
				for i := 0; i < 2; i++ {
					tr.Record("203.0.113.7", "real@victim.example")
				}
				findings = tr.recordSuccessAt("203.0.113.7", "real@victim.example", at, knownCustomerIMAP, true)
			}
			f := onlyCheck(t, findings, "mail_account_compromised")
			if f.Severity != alert.Critical || f.BlockTTL != time.Hour || !f.Timestamp.Equal(at) {
				t.Errorf("spray compromise = %+v, want Critical with spray block duration at %s", f, at)
			}
			observeMailboxSignal(cfg, "real@victim.example", newCountry("RU", now))
			got := stolenLoginResponses(cfg, findings)
			e, err := db.GetMailboxEvidence("real@victim.example")
			if err != nil || len(got) != 0 || len(*calls) != 0 || len(e.Signals) != 1 || e.Signals[0].Kind != signalNewCountry {
				t.Fatalf("expired spray login acted: findings=%+v calls=%v ledger=%+v err=%v", got, *calls, e, err)
			}
		})
	}
}

// The backend's account and its fallback lookup must survive an unavailable
// or stale generic owner cache. The claim still names only the mailbox.
func TestCrackIncidentPreservesResponseOwner(t *testing.T) {
	for _, owner := range []string{"", "oldowner"} {
		for _, mode := range []string{"live", "failed", "dry-run"} {
			t.Run(owner+"/"+mode, func(t *testing.T) {
				evidenceCase(t)
				t.Cleanup(checks.SetAccountOwnerLookupForTest(func(string) (string, bool) {
					return owner, owner != ""
				}))
				cfg := eximAutoHoldConfig()
				switch mode {
				case "dry-run":
					cfg = dryRunConfig()
				case "failed":
					stubMailboxActions(t, func([]string) ([]byte, error) { return uapiFailure("denied") })
				}
				observeMailboxSignal(cfg, "real@victim.example", newCountry("RU", time.Now()))
				f := onlyIncident(t, stolenLoginResponses(cfg, []alert.Finding{stolenLogin("real@victim.example", alert.Critical)}))
				if f.TenantID != "cpuser" {
					t.Errorf("tenant = %q, want the response owner cpuser", f.TenantID)
				}
				if !reflect.DeepEqual(f.Claims, []admission.Claim{{Kind: admission.ClaimMailbox, Value: "real@victim.example"}}) {
					t.Errorf("claims = %+v, want only the authenticated mailbox", f.Claims)
				}
			})
		}
	}
}
