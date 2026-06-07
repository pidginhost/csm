package daemon

import (
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/store"
)

// primeOutboundWindow seeds the authenticated-send rate window for a mailbox
// with n timestamps at the current time, so domainHasOutboundBlast observes
// real outbound volume for that mailbox's domain.
func primeOutboundWindow(user string, n int) {
	rw := &rateWindow{}
	now := time.Now()
	for i := 0; i < n; i++ {
		rw.add(now)
	}
	emailRateWindows.Store(user, rw)
}

// A cPanel defer/fail governor trip with no corroborating outbound volume is a
// deliverability event, not a spam outbreak. cPanel has already throttled the
// domain by the time exim logs this line, and the same governor fires on
// inbound junk, full mailboxes, and bounce backscatter. CSM must report it as
// email_defer_fail_governor (High) and must NOT auto-hold, so an operator who
// clears a false-positive hold is not immediately re-held.
func TestParseEximLogLine_MaxDefers_NoOutboundEvidence_Governor(t *testing.T) {
	resetEmailRateState()

	prevHook := autoSuspendOutgoingMail
	var holds []string
	autoSuspendOutgoingMail = func(target string) bool { holds = append(holds, target); return true }
	t.Cleanup(func() { autoSuspendOutgoingMail = prevHook })

	cfg := eximAutoHoldConfig() // auto-response live, but no outbound rate data
	cfg.EmailProtection.RateWarnThreshold = 50
	cfg.EmailProtection.RateWindowMin = 60

	line := `2026-06-07 07:51:17 Domain membranaepdm.ro has exceeded the max defers and failures per hour (15/15 (100%)) allowed. Message discarded.`

	withGlobalStore(t, func(_ *store.DB) {
		findings := parseEximLogLine(line, cfg)

		var gotGovernor, gotOutbreak bool
		for _, f := range findings {
			switch f.Check {
			case "email_defer_fail_governor":
				gotGovernor = true
				if f.Severity != alert.High {
					t.Errorf("governor finding severity = %v, want High", f.Severity)
				}
				if f.Domain != "membranaepdm.ro" {
					t.Errorf("governor finding domain = %q, want membranaepdm.ro", f.Domain)
				}
			case "email_spam_outbreak":
				gotOutbreak = true
			}
		}
		if !gotGovernor {
			t.Errorf("expected email_defer_fail_governor finding, got %v", findings)
		}
		if gotOutbreak {
			t.Error("governor trip with no outbound volume must not be classified as spam outbreak")
		}
	})

	if len(holds) != 0 {
		t.Fatalf("governor trip must not auto-hold; got holds %v", holds)
	}
}

// When CSM's own authenticated-send rate window shows a real outbound blast for
// the domain, the governor line is genuine corroboration: keep the CRITICAL
// email_spam_outbreak classification and auto-hold the account.
func TestParseEximLogLine_MaxDefers_RealOutbreak_HoldsAndCriticals(t *testing.T) {
	resetEmailRateState()

	prevHook := autoSuspendOutgoingMail
	var holds []string
	autoSuspendOutgoingMail = func(target string) bool { holds = append(holds, target); return true }
	t.Cleanup(func() { autoSuspendOutgoingMail = prevHook })

	cfg := eximAutoHoldConfig()
	cfg.EmailProtection.RateWarnThreshold = 50
	cfg.EmailProtection.RateWindowMin = 60

	primeOutboundWindow("spammer@blast.example", 120)

	line := `2026-06-07 08:00:00 Domain blast.example has exceeded the max defers and failures per hour (15/15 (100%)) allowed. Message discarded.`

	withGlobalStore(t, func(_ *store.DB) {
		findings := parseEximLogLine(line, cfg)

		var gotOutbreak bool
		for _, f := range findings {
			if f.Check == "email_spam_outbreak" {
				gotOutbreak = true
				if f.Severity != alert.Critical {
					t.Errorf("outbreak severity = %v, want Critical", f.Severity)
				}
			}
			if f.Check == "email_defer_fail_governor" {
				t.Error("corroborated outbreak must not downgrade to governor finding")
			}
		}
		if !gotOutbreak {
			t.Errorf("expected email_spam_outbreak finding, got %v", findings)
		}
	})

	if len(holds) != 1 || holds[0] != "blast.example" {
		t.Fatalf("real outbreak should auto-hold the domain once, got %v", holds)
	}
}
