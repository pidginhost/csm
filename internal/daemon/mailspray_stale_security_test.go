package daemon

import (
	"fmt"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

// Clean logins beside one failing mailbox may earn their own trust, but
// standing earned during the attack cannot downgrade a crack of its victim.
func TestMailStaleExceptionDoesNotDowngradeVictimCrack(t *testing.T) {
	const ip, victim = "203.0.113.173", "victim@example.com"
	for _, proto := range []string{"imap", "pop3"} {
		t.Run(proto, func(t *testing.T) {
			d, clock := newPairingDaemon(t, sprayTestConfig("enforce"))
			feed(d, clock, makeDovecotFailLine(proto, ip, victim))
			for _, mailbox := range []string{"owned1@example.com", "owned2@example.com"} {
				feed(d, clock, makeDovecotSuccessLine(proto, ip, mailbox))
			}
			clock.advance(11 * time.Minute)
			feed(d, clock, makeDovecotFailLine(proto, ip, victim), makeDovecotFailLine(proto, ip, victim))
			got := feed(d, clock, makeDovecotSuccessLine(proto, ip, victim))
			f, ok := findingByCheck(got, "mail_account_compromised")
			if !ok || f.Severity != alert.Critical {
				t.Fatalf("standing earned during victim failures downgraded its crack: %+v", got)
			}
			if sprayHasTrust(d, ip, victim) {
				t.Fatal("cracked victim earned trust")
			}
		})
	}
}

// Standing earned after failures began cannot turn a corroborated missing
// mailbox into an office typo or downgrade the resulting compromise.
func TestMailStaleExceptionDoesNotDowngradeMissingMailbox(t *testing.T) {
	const victim, missing = "victim@example.com", "missing@example.com"
	for _, tc := range []struct {
		name, source, login string
	}{
		{"IPv4", "192.0.2.173", "192.0.2.173"},
		{"IPv6 siblings", "2001:db8:1::173", "2001:db8:1::174"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := testSprayConfig()
			cfg.BreadthMailboxes = 3
			m, clock := newTestSpray(cfg)
			wantNoVerdict(t, m.Failure(tc.source, victim, mailboxExists))
			clock.advance(time.Second)
			m.Success(tc.login, "owned1@example.com")
			m.Success(tc.login, "owned2@example.com")
			clock.advance(61 * time.Minute)
			m = restartSpray(t, m, clock)
			corroborate(t, m, missing)
			wantRule(t, m.Failure(tc.source, missing, mailboxMissing), sprayRuleMissingMailbox, true)
			clean, v := m.Success(tc.login, victim)
			if clean {
				t.Fatal("login after a corroborated missing mailbox earned trust")
			}
			wantRule(t, v, sprayRuleCompromise, true)
		})
	}
}

// SMTP logins share the same evidence even when failures arrive through the
// other MTA reader. A success on the victim remains a blocking compromise.
func TestSMTPStaleExceptionDoesNotDowngradeCompromise(t *testing.T) {
	const ip, victim, missing = "192.0.2.173", "victim@example.com", "missing@example.com"
	for name, src := range smtpLoginSources {
		t.Run(name, func(t *testing.T) {
			d, clock := newPairingDaemon(t, sprayTestConfig("enforce"))
			src.feed(d, clock, src.failure(ip, victim)...)
			for _, mailbox := range []string{"owned1@example.com", "owned2@example.com"} {
				src.feed(d, clock, src.login(ip, mailbox)...)
			}
			clock.advance(61 * time.Minute)
			for _, source := range []string{"198.51.100.173", "203.0.113.173", ip} {
				feed(d, clock, "dovecot: auth: sql("+missing+","+source+"): unknown user",
					fmt.Sprintf(postfixFailFmt, source, missing))
			}
			got := src.feed(d, clock, src.login(ip, victim)...)
			f, ok := findingByCheck(got, "mail_account_compromised")
			if !ok || f.Severity != alert.Critical || f.BlockTTL <= 0 {
				t.Fatalf("standing earned during victim failures downgraded SMTP compromise: %+v", got)
			}
			if sprayHasTrust(d, ip, victim) {
				t.Fatal("compromised victim earned trust")
			}
		})
	}
}
