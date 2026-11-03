package daemon

import (
	"fmt"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

// smtpSuccessIPs lists the addresses holding login trust from a successful
// login.
func smtpSuccessIPs(d *Daemon) map[string]bool {
	d.mailSpray.mu.Lock()
	defer d.mailSpray.mu.Unlock()
	out := map[string]bool{}
	for k := range d.mailSpray.trust {
		out[k.ip] = true
	}
	return out
}

// An address whose users log in to the mailboxes it fails on is a live
// office, not a mailbox walker, so those mistyped passwords must not add up
// to the slow block. A login to some other mailbox vouches for nothing else.
// The spray rules are off, so only the slow path can fire.
func TestPostfixSASLSuccessDisqualifiesSlowBrute(t *testing.T) {
	const ip = "203.0.113.110"
	account := func(i int) string { return fmt.Sprintf("user%02d@example.net", i) }
	for _, tc := range []struct {
		name   string
		logins []string
		fires  bool
	}{
		{"no login", nil, true},
		{"login to another mailbox", []string{"carol@example.net"}, true},
		{"login to every failing mailbox", []string{account(0), account(1), account(2), account(3), account(4), account(5), account(6), account(7), account(8), account(9)}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d, clock := newPairingDaemon(t, sprayTestConfig("off"))
			for _, user := range tc.logins {
				feed(d, clock, "postfix/submission/smtpd[77]: 4XyZ1a2B3c: client=unknown["+ip+"], sasl_method=PLAIN, sasl_username="+user)
			}
			clock.advance(11 * time.Minute) // trust ages past the failure window
			var got []alert.Finding
			for i := 0; i < slowBruteWalkAccounts; i++ {
				clock.advance(8 * time.Minute)
				got = append(got, feed(d, clock,
					"dovecot: auth: sql("+account(i)+","+ip+"): Password mismatch",
					fmt.Sprintf(postfixFailFmt, ip, account(i)))...)
			}
			if calls := smtpCalls(d); calls != int64(slowBruteWalkAccounts) {
				t.Fatalf("SMTP failures = %d, want %d", calls, slowBruteWalkAccounts)
			}
			if _, fired := findingByCheck(got, "smtp_bruteforce"); fired != tc.fires {
				t.Fatalf("smtp_bruteforce fired = %v, want %v: %+v", fired, tc.fires, got)
			}
		})
	}
}

func TestPostfixSASLSuccessLineFormats(t *testing.T) {
	cases := []struct {
		name, line, ip string
	}{
		{"smtpd classic timestamp", "Oct 31 20:44:15 mail postfix/smtpd[1234]: 4F2B91A0123: client=mx.example.net[203.0.113.111], sasl_method=LOGIN, sasl_username=alice@example.net", "203.0.113.111"},
		{"submission long queue id", "2026-10-31T20:44:15.494854+00:00 mail postfix/submission/smtpd[2207002]: 4cZ8Lw1qXvz9sQ: client=unknown[203.0.113.112], sasl_method=PLAIN, sasl_username=alice@example.net", "203.0.113.112"},
		{"ipv6 client", "postfix/smtps/smtpd[99]: 4ABC123: client=unknown[2001:db8::113], sasl_method=PLAIN, sasl_username=a", "2001:db8::113"},
		{"client port logging", "postfix/smtpd[99]: 4ABC123: client=unknown[203.0.113.114]:51234, sasl_method=PLAIN, sasl_username=a", "203.0.113.114"},
		{"client port logging ipv6", "postfix/smtpd[99]: 4ABC123: client=unknown[2001:db8::115]:51234, sasl_method=PLAIN, sasl_username=a", "2001:db8::115"},
		{"ipv4-mapped client", "postfix/smtpd[99]: 4ABC123: client=unknown[::ffff:203.0.113.116], sasl_method=PLAIN, sasl_username=a", "203.0.113.116"},
		{"sender and forwarding fields", "postfix/smtpd[99]: 4ABC123: client=unknown[203.0.113.117], sasl_method=PLAIN, sasl_username=a, sasl_sender=b@example.net, orig_queue_id=4DEF456, orig_client=unknown[198.51.100.9]", "203.0.113.117"},
		{"username names another client", "postfix/smtpd[99]: 4ABC123: client=unknown[203.0.113.118], sasl_method=PLAIN, sasl_username=x, client=unknown[198.51.100.9], sasl_method=PLAIN", "203.0.113.118"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d, clock := newPairingDaemon(t, sprayTestConfig("enforce"))
			if got := feed(d, clock, tc.line); len(got) != 0 {
				t.Fatalf("success raised findings: %+v", got)
			}
			if got := smtpSuccessIPs(d); len(got) != 1 || !got[tc.ip] {
				t.Fatalf("successful logins = %v, want only %s", got, tc.ip)
			}
			if calls := smtpCalls(d); calls != 0 {
				t.Fatalf("success counted %d failures", calls)
			}
		})
	}
}

// Trust is per mailbox, so the success line must yield the login name and
// nothing smtpd appends after it.
func TestPostfixSASLSuccessUser(t *testing.T) {
	const base = "4ABC123: client=unknown[203.0.113.5], sasl_method=PLAIN"
	cases := []struct {
		name, msg, ip, user string
	}{
		{"login name", base + ", sasl_username=alice@example.com", "203.0.113.5", "alice@example.com"},
		{"sender appended", base + ", sasl_username=alice@example.com, sasl_sender=bob@example.com", "203.0.113.5", "alice@example.com"},
		{"forwarding fields appended", base + ", sasl_username=alice@example.com, orig_queue_id=4DEF456, orig_client=unknown[198.51.100.9]", "203.0.113.5", "alice@example.com"},
		{"all fields appended", base + ", sasl_username=alice@example.com, sasl_sender=bob@example.com, orig_queue_id=4DEF456, orig_client=unknown[198.51.100.9]", "203.0.113.5", "alice@example.com"},
		{"no login name", base, "203.0.113.5", ""},
		{"forwarding client only", base + ", sasl_username=alice@example.com, orig_client=unknown[198.51.100.9]", "203.0.113.5", "alice@example.com"},
		{"earliest field regardless of order", base + ", sasl_username=alice@example.com, orig_client=unknown[198.51.100.9], sasl_sender=bob@example.com", "203.0.113.5", "alice@example.com"},
		{"empty login name", base + ", sasl_username=, sasl_sender=bob@example.com", "203.0.113.5", ""},
		{"sender cannot supply missing login name", base + ", sasl_sender=bob, sasl_username=alice@example.com", "203.0.113.5", ""},
		{"forwarding cannot supply missing login name", base + ", orig_queue_id=x, sasl_username=alice@example.com", "203.0.113.5", ""},
		{"not a success line", "warning: unknown[203.0.113.5]: SASL PLAIN authentication failed: , sasl_username=alice@example.com", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ip, user := postfixSASLSuccess(tc.msg)
			if ip != tc.ip || user != tc.user {
				t.Fatalf("postfixSASLSuccess = (%q, %q), want (%q, %q)", ip, user, tc.ip, tc.user)
			}
		})
	}
}

// Only smtpd's own queue record of an authenticated client is a success.
// Client text echoed into other lines must not vouch for an address.
func TestPostfixSASLSuccessLinesThatMustNotCount(t *testing.T) {
	cases := []struct {
		name, line string
	}{
		{"unauthenticated client", "postfix/smtpd[99]: 4ABC123: client=unknown[203.0.113.120]"},
		{"forwarded unauthenticated client", "postfix/smtpd[99]: 4ABC123: client=localhost[127.0.0.1], orig_queue_id=4DEF456, orig_client=unknown[203.0.113.121]"},
		{"client text in warning", "postfix/smtpd[99]: warning: Illegal address syntax from unknown[198.51.100.9] in RCPT command: <x: client=unknown[203.0.113.122], sasl_method=PLAIN, sasl_username=y>"},
		{"client text in reject", "postfix/smtpd[99]: NOQUEUE: reject: RCPT from unknown[198.51.100.9]: 554 5.7.1 <x: client=unknown[203.0.113.122], sasl_method=PLAIN, sasl_username=y>: Relay access denied; from=<a@example.net> to=<x: client=unknown[203.0.113.122], sasl_method=PLAIN, sasl_username=y> proto=ESMTP helo=<h>"},
		{"postfix non-smtpd", "postfix/qmqpd[99]: 4ABC123: client=unknown[203.0.113.123], sasl_method=PLAIN, sasl_username=a"},
		{"other program", "dovecot: 4ABC123: client=unknown[203.0.113.123], sasl_method=PLAIN, sasl_username=a"},
		{"space in client field", "postfix/smtpd[99]: 4ABC123: client=unknown [203.0.113.124], sasl_method=PLAIN, sasl_username=a"},
		{"not an address", "postfix/smtpd[99]: 4ABC123: client=unknown[localhost], sasl_method=PLAIN, sasl_username=a"},
		{"infra address", "postfix/smtpd[99]: 4ABC123: client=unknown[192.0.2.10], sasl_method=PLAIN, sasl_username=a"},
		{"private address", "postfix/smtpd[99]: 4ABC123: client=unknown[10.0.0.7], sasl_method=PLAIN, sasl_username=a"},
		{"loopback address", "postfix/smtpd[99]: 4ABC123: client=localhost[127.0.0.1], sasl_method=PLAIN, sasl_username=a"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := sprayTestConfig("enforce")
			cfg.InfraIPs = []string{"192.0.2.10"}
			d, clock := newPairingDaemon(t, cfg)
			if got := feed(d, clock, tc.line); len(got) != 0 {
				t.Fatalf("findings = %+v, want none", got)
			}
			if got := smtpSuccessIPs(d); len(got) != 0 {
				t.Fatalf("successful logins = %v, want none", got)
			}
		})
	}
}

// Exim logs its own authenticated deliveries.
func TestPostfixSASLSuccessSkippedOnEximHosts(t *testing.T) {
	d, clock := newPairingDaemon(t, sprayTestConfig("enforce"))
	d.smtpAuthFromExim = true
	feed(d, clock, "postfix/smtpd[99]: 4ABC123: client=unknown[203.0.113.125], sasl_method=PLAIN, sasl_username=a")
	if got := smtpSuccessIPs(d); len(got) != 0 {
		t.Fatalf("successful logins = %v, want none", got)
	}
}

// A working account must not erase the fast failure counter, even when each
// guess is followed by a successful login using that account.
func TestPostfixSASLSuccessDoesNotSuppressFastBrute(t *testing.T) {
	const ip = "203.0.113.126"
	d, clock := newPairingDaemon(t, &config.Config{})
	var got []alert.Finding
	for i := 0; i < d.smtpAuthTracker.perIPThreshold; i++ {
		got = append(got, feed(d, clock,
			"dovecot: auth: sql(target@example.net,"+ip+"): Password mismatch",
			fmt.Sprintf(postfixFailFmt, ip, "target@example.net"),
			"postfix/smtpd[99]: 4ABC123: client=unknown["+ip+"], sasl_method=PLAIN, sasl_username=owned@example.net")...)
	}
	if len(got) != 1 || got[0].Check != "smtp_bruteforce" || got[0].SourceIP != ip {
		t.Fatalf("findings = %+v, want one fast brute-force finding", got)
	}
	if calls := smtpCalls(d); calls != int64(d.smtpAuthTracker.perIPThreshold) {
		t.Fatalf("success lost failures: got %d calls", calls)
	}
}

// Login trust, like Exim's, expires with the spray memory window.
func TestPostfixSASLSuccessExemptionExpires(t *testing.T) {
	const ip = "203.0.113.127"
	cfg := sprayTestConfig("off")
	d, clock := newPairingDaemon(t, cfg)
	for i := 0; i < slowBruteWalkAccounts; i++ {
		feed(d, clock, "postfix/smtpd[99]: 4ABC123: client=unknown["+ip+"], sasl_method=PLAIN, sasl_username="+fmt.Sprintf("user%02d@example.net", i))
	}
	clock.advance(time.Duration(cfg.Thresholds.MailSprayWindowMin) * time.Minute)
	var got []alert.Finding
	for i := 0; i < slowBruteWalkAccounts; i++ {
		clock.advance(8 * time.Minute)
		account := fmt.Sprintf("user%02d@example.net", i)
		got = append(got, feed(d, clock,
			"dovecot: auth: sql("+account+","+ip+"): Password mismatch",
			fmt.Sprintf(postfixFailFmt, ip, account))...)
	}
	if len(got) != 1 || got[0].Check != "smtp_bruteforce" || got[0].SourceIP != ip {
		t.Fatalf("findings = %+v, want one slow brute-force finding after expiry", got)
	}
}
