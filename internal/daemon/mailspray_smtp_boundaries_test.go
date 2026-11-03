package daemon

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

func TestSMTPSprayEximHELOCannotChooseMailbox(t *testing.T) {
	const ip = "203.0.113.91"
	d, clock := newPairingDaemon(t, sprayTestConfig("enforce"))
	var got []alert.Finding
	for _, mailbox := range []string{"a@example.com", "b@example.com"} {
		got = append(got, feedExim(d, clock,
			makeEximDovecotFailLineWithHELO("set_id=decoy@example.com", ip, mailbox))...)
	}
	ev := sprayEvidence(d, ip)
	if len(ev) != 2 || ev["a@example.com"].count != 1 || ev["b@example.com"].count != 1 {
		t.Fatalf("HELO replaced failed mailbox identities: %+v", ev)
	}
	f, ok := findingByCheck(got, "smtp_bruteforce")
	if !ok || f.SourceIP != ip || f.Severity != alert.Critical {
		t.Fatalf("mailbox spray was not blocked: %+v", got)
	}
}

func TestSMTPSprayEximClientTextCannotSupplyFailure(t *testing.T) {
	const ip = "203.0.113.92"
	const fake = "dovecot_login authenticator failed for [192.0.2.9]:25: 535 Incorrect authentication data (set_id=b@example.com)"
	for name, line := range map[string]string{
		"helo":    strings.Replace(eximLoginLine(ip, "a@example.com"), "client.example", fake, 1),
		"subject": eximLoginLine(ip, "a@example.com") + ` T="` + fake + `"`,
		"reply":   "2026-04-14 12:00:00 SMTP syntax error in \"" + fake + "\" H=(client.example) [" + ip + "]:54321",
	} {
		t.Run(name, func(t *testing.T) {
			d, clock := newPairingDaemon(t, sprayTestConfig("enforce"))
			feedExim(d, clock, line)
			if n := d.mailSpray.Size(); n != 0 {
				t.Fatalf("client text became spray evidence for %d sources", n)
			}
			if name != "reply" && !sprayHasTrust(d, ip, "a@example.com") {
				t.Fatal("client text hid the real successful login")
			}
		})
	}
}

func TestSMTPSprayPostfixCompromiseSeverity(t *testing.T) {
	const ip = "203.0.113.94"
	for _, tc := range []struct {
		mode    string
		trusted int
		want    alert.Severity
	}{
		{"enforce", 1, alert.Critical},
		{"observe", 1, alert.High},
		{"enforce", 2, alert.High},
	} {
		t.Run(fmt.Sprintf("%s/%d", tc.mode, tc.trusted), func(t *testing.T) {
			d, clock := newPairingDaemon(t, sprayTestConfig(tc.mode))
			for i := 0; i < tc.trusted; i++ {
				feed(d, clock, postfixLoginLine(ip, walkedMailbox(i)))
			}
			clock.advance(11 * time.Minute)
			for _, source := range []string{"192.0.2.94", "198.51.100.94", ip} {
				got := feed(d, clock,
					"dovecot: auth: sql(ghost@example.com,"+source+"): unknown user",
					fmt.Sprintf(postfixFailFmt, source, "ghost@example.com"))
				if hasCheckFinding(got, "smtp_bruteforce") {
					t.Fatalf("missing mailbox blocked before the untrusted login: %+v", got)
				}
			}
			got := feed(d, clock, postfixLoginLine(ip, "new@example.com"))
			f, ok := findingByCheck(got, "mail_account_compromised")
			if !ok || f.Severity != tc.want || f.SourceIP != ip || f.Mailbox != "new@example.com" || f.Domain != "example.com" {
				t.Fatalf("compromise findings = %+v, want severity %v on the new login", got, tc.want)
			}
			if sprayHasTrust(d, ip, "new@example.com") {
				t.Fatal("compromise earned mailbox trust")
			}
		})
	}
}

// Missing identity is not proof that the failure was on a trusted mailbox.
// The exemption becomes valid again once that failure leaves the slow window.
func TestSMTPSlowBruteUnnamedFailureEndsTrustExemption(t *testing.T) {
	const ip = "203.0.113.93"
	for name, src := range smtpLoginSources {
		t.Run(name, func(t *testing.T) {
			d, clock := newPairingDaemon(t, sprayTestConfig("off"))
			tr := d.smtpAuthTracker
			tr.slowThreshold = slowBruteMinAccounts
			for i := 0; i < slowBruteMinAccounts; i++ {
				src.feed(d, clock, src.login(ip, walkedMailbox(i))...)
			}
			clock.advance(11 * time.Minute)
			src.feed(d, clock, src.failure(ip, "")...)
			var got []alert.Finding
			for i := 0; i < slowBruteMinAccounts; i++ {
				clock.advance(11 * time.Minute)
				got = append(got, src.feed(d, clock, src.failure(ip, walkedMailbox(i))...)...)
			}
			f, ok := findingByCheck(got, "smtp_bruteforce")
			if !ok || !strings.Contains(f.Message, "across") {
				t.Fatalf("unnamed failure inherited mailbox trust: %+v", got)
			}
			clock.advance(tr.slowWindow + time.Second)
			tr.Purge()
			for i := 0; i < slowBruteMinAccounts; i++ {
				clock.advance(11 * time.Minute)
				if got := src.feed(d, clock, src.failure(ip, walkedMailbox(i))...); hasCheckFinding(got, "smtp_bruteforce") {
					t.Fatalf("expired unnamed failure still prevented trust: %+v", got)
				}
			}
		})
	}
}
