package daemon

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/store"
)

// A spray split across spellings of one mailbox ("User@", "user@", padded)
// is one target, as the SMTP tracker already counts it. Folding only the
// domain let each spelling stay below the distinct-source threshold.
func TestMailAccountSprayFoldsMailboxSpellings(t *testing.T) {
	now := time.Date(2026, 11, 12, 10, 0, 0, 0, time.UTC)
	tr := newMailAuthTracker(1000, 1000, 3, 10*time.Minute, time.Hour, 0, 0, 10000, func() time.Time { return now })
	spellings := []string{"Alice@Example.COM", "alice@example.com", " ALICE@example.com "}
	var sprays int
	for i, account := range spellings {
		for _, f := range tr.Record(fmt.Sprintf("203.0.113.%d", 10+i), account) {
			if f.Check == "mail_account_spray" {
				sprays++
				if f.Mailbox != "alice@example.com" {
					t.Errorf("spray names %q, want the folded mailbox", f.Mailbox)
				}
			}
		}
	}
	if sprays != 1 {
		t.Fatalf("mail_account_spray findings = %d, want 1 across three spellings", sprays)
	}
}

func TestNormalizeMailAuthAccountMatchesSMTPFold(t *testing.T) {
	for _, tt := range []struct{ in, want string }{
		{"Alice@Example.COM", "alice@example.com"},
		{" bob@example.net\t", "bob@example.net"},
		{"CPUSER", "cpuser"},
		{"\u0130nfo@Example.COM", "\u0130nfo@example.com"},
		{"\u212aate@example.com", "\u212aate@example.com"},
		{"\xffUSER@example.com", ""},
		{"", ""},
	} {
		if got := normalizeMailAuthAccount(tt.in); got != tt.want {
			t.Errorf("normalizeMailAuthAccount(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestMailAccountFoldKeepsDistinctSlowTargets(t *testing.T) {
	for _, smtp := range []bool{false, true} {
		t.Run(fmt.Sprintf("smtp=%t", smtp), func(t *testing.T) {
			now := time.Date(2026, 11, 12, 12, 0, 0, 0, time.UTC)
			var record func(string, string) []alert.Finding
			check := "mail_bruteforce"
			if smtp {
				tr := newSMTPAuthTracker(0, 0, 0, time.Minute, time.Hour, 3, time.Hour, 1000, func() time.Time { return now })
				record, check = tr.Record, "smtp_bruteforce"
			} else {
				tr := newMailAuthTracker(0, 0, 0, time.Minute, time.Hour, 3, time.Hour, 1000, func() time.Time { return now })
				record = tr.Record
			}
			var findings []alert.Finding
			for _, account := range []string{"info@example.com", "\u0130nfo@example.com", "other@example.com"} {
				findings = append(findings, record("192.0.2.53", account)...)
			}
			if f := onlyCheck(t, findings, check); f.Severity != alert.Critical {
				t.Fatalf("distinct slow targets did not block: %+v", f)
			}
		})
	}
}

func TestMailAccountFoldPreservesAuthenticatedIdentity(t *testing.T) {
	for _, tt := range []struct {
		name, login, mailbox, domain, owner string
		claim                               admission.ClaimKind
	}{
		{"mailbox", "Alice@Example.COM", "Alice@example.com", "example.com", "owner", admission.ClaimMailbox},
		{"hosting account", "CPUser", "CPUser", "", "CPUser", admission.ClaimAccount},
	} {
		t.Run(tt.name, func(t *testing.T) {
			clock := &staticClock{t: time.Date(2026, 11, 12, 12, 0, 0, 0, time.UTC)}
			tr := newTestMailTracker(t, clock)
			t.Cleanup(checks.SetAccountOwnerLookupForTest(func(domain string) (string, bool) {
				if domain == tt.domain {
					return tt.owner, true
				}
				return "", false
			}))
			t.Cleanup(checks.SetHostingAccountLookupForTest(func(name string) string {
				if name == tt.mailbox {
					return name
				}
				return ""
			}))
			for i := 0; i < 3; i++ {
				tr.Record("192.0.2.50", tt.login)
			}
			findings := tr.RecordSuccess("192.0.2.50", tt.login)
			f := onlyCheck(t, findings, "mail_account_compromised")
			if f.Severity != alert.Critical || f.Mailbox != tt.mailbox || f.Domain != tt.domain || f.TenantID != tt.owner {
				t.Errorf("compromise lost authenticated identity: %+v", f)
			}
			claimValue := tt.mailbox
			if tt.claim == admission.ClaimAccount {
				claimValue = tt.owner
			}
			if len(f.Claims) != 1 || f.Claims[0] != (admission.Claim{Kind: tt.claim, Value: claimValue}) {
				t.Errorf("claims = %+v, want authenticated identity", f.Claims)
			}
			if !strings.Contains(f.Message, tt.mailbox) {
				t.Errorf("message lost authenticated identity: %q", f.Message)
			}
			withMailboxStore(t)
			withMailBackendHost(t, true)
			var subjects []string
			withLifecycleBackend(t, lifecycleBackend{
				suspendFn: func(c mailboxCompromise) (store.MailboxSuspension, error) {
					subjects = append(subjects, c.Subject)
					return store.MailboxSuspension{Account: tt.owner, Kind: store.SuspensionKindMailbox}, nil
				},
			})
			stolenLoginResponses(eximAutoHoldConfig(), findings)
			if len(subjects) != 1 || subjects[0] != tt.mailbox {
				t.Errorf("response subjects = %q, want %q", subjects, tt.mailbox)
			}
		})
	}
}

func TestMailAccountFoldDetectsCrackAcrossSpellings(t *testing.T) {
	clock := &staticClock{t: time.Date(2026, 11, 12, 12, 0, 0, 0, time.UTC)}
	tr := newTestMailTracker(t, clock)
	const ip = "192.0.2.55"
	tr.Record(ip, "ALICE@Example.COM")
	tr.Record(ip, " alice@example.com ")
	f := onlyCheck(t, tr.RecordSuccess(ip, "Alice@Example.COM"), "mail_account_compromised")
	if f.Severity != alert.Critical || f.Mailbox != "Alice@example.com" {
		t.Fatalf("case variants hid a compromise: %+v", f)
	}
	if got := tr.RecordSuccess(ip, " ALICE@example.com "); len(got) != 0 {
		t.Fatalf("case variant bypassed compromise suppression: %+v", got)
	}
	if got := tr.ExportGoodSource()[ip]; len(got) != 0 {
		t.Fatalf("cracked mailbox earned standing: %+v", got)
	}
}

func TestMailAccountFoldSprayReplacementPreservesIdentity(t *testing.T) {
	withOwnerTable(t)
	clock := &staticClock{t: time.Date(2026, 11, 12, 12, 0, 0, 0, time.UTC)}
	tr := newTestMailTracker(t, clock)
	cfg := testSprayConfig()
	cfg.BlockTTL = time.Hour
	tr.SetSpray(newMailSpray(cfg, clock.Now))
	const ip = "192.0.2.54"
	const missing = "missing@example.net"
	corroborate(t, tr.spray, missing)
	tr.RecordResolvedObserved(ip, missing, sprayMailbox{name: missing, exist: mailboxMissing}, alert.Observation{})
	for _, account := range []string{"ALICE@Example.COM", " alice@example.com ", "Alice@example.com"} {
		tr.Record(ip, account)
	}
	f := onlyCheck(t, tr.RecordSuccess(ip, "Alice@Example.COM"), "mail_account_compromised")
	if f.Severity != alert.Critical || f.BlockTTL != cfg.BlockTTL {
		t.Fatalf("spray verdict did not replace the short-window finding: %+v", f)
	}
	if f.Mailbox != "Alice@example.com" || f.Domain != "example.com" || f.TenantID != "alice" || !strings.Contains(f.Message, "Alice@example.com") {
		t.Fatalf("spray replacement lost authenticated identity: %+v", f)
	}
}

// Unicode characters that lower to another name must not borrow its standing.
func TestMailAccountFoldDoesNotTransferTrust(t *testing.T) {
	for _, tt := range []struct{ trusted, target string }{
		{"\u0130nfo@example.com", "info@example.com"},
		{"info@example.com", "\u0130nfo@example.com"},
		{"\u212aate@example.com", "kate@example.com"},
		{"\u00c4nne@example.com", "\u00e4nne@example.com"},
	} {
		for _, restored := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/%t", tt.trusted, restored), func(t *testing.T) {
				clock := &staticClock{t: time.Date(2026, 11, 12, 12, 0, 0, 0, time.UTC)}
				tr := newTestMailTracker(t, clock)
				const ip = "192.0.2.51"
				if restored {
					tr.LoadGoodSource(goodSourceSnapshot{ip: {tt.trusted: {
						First: clock.Now().Add(-time.Hour), Last: clock.Now().Add(-time.Minute),
					}}}, clock.Now())
				} else {
					tr.RecordSuccess(ip, tt.trusted)
					clock.advance(time.Hour)
				}
				var findings []alert.Finding
				for i := 0; i < tr.perIPThreshold; i++ {
					findings = append(findings, tr.Record(ip, tt.target)...)
				}
				if f := onlyCheck(t, findings, "mail_bruteforce"); f.Severity != alert.Critical {
					t.Fatalf("distinct mailbox did not block: %+v", f)
				}
				if f := onlyCheck(t, tr.RecordSuccess(ip, tt.target), "mail_account_compromised"); f.Severity != alert.Critical {
					t.Fatalf("distinct mailbox compromise was suppressed: %+v", f)
				}
			})
		}
	}
}

func TestMailAccountFoldRestoresMixedCaseStanding(t *testing.T) {
	clock := &staticClock{t: time.Date(2026, 11, 12, 12, 0, 0, 0, time.UTC)}
	tr := newTestMailTracker(t, clock)
	const ip = "192.0.2.52"
	first, last := clock.Now().Add(-time.Hour), clock.Now().Add(-time.Minute)
	tr.LoadGoodSource(goodSourceSnapshot{ip: {
		"Alice@Example.COM":   {First: first, Last: first},
		" ALICE@example.com ": {First: last, Last: last}, //nolint:gocritic // Legacy snapshots can retain surrounding whitespace.
	}}, clock.Now())
	got := tr.ExportGoodSource()[ip]
	if len(got) != 1 || got["alice@example.com"] != (goodSourceTimes{First: first, Last: last}) {
		t.Fatalf("restored standing = %+v, want one merged mailbox", got)
	}
	var findings []alert.Finding
	for i := 0; i < tr.perIPThreshold; i++ {
		findings = append(findings, tr.Record(ip, "alice@EXAMPLE.COM")...)
	}
	if len(findings) != 1 || findings[0].Check != "mail_bruteforce_suspected" {
		t.Fatalf("restored mailbox standing did not excuse stale passwords: %+v", findings)
	}
}

func TestMailAccountFoldMalformedNameCannotBorrowTrust(t *testing.T) {
	clock := &staticClock{t: time.Date(2026, 11, 12, 12, 0, 0, 0, time.UTC)}
	tr := newTestMailTracker(t, clock)
	const ip = "192.0.2.56"
	tr.RecordSuccess(ip, "\ufffduser@example.com")
	clock.advance(time.Hour)
	var findings []alert.Finding
	for i := 0; i < tr.perIPThreshold; i++ {
		findings = append(findings, tr.Record(ip, "\xffuser@example.com")...)
	}
	if f := onlyCheck(t, findings, "mail_bruteforce"); f.Severity != alert.Critical {
		t.Fatalf("malformed account borrowed login trust: %+v", f)
	}
}
