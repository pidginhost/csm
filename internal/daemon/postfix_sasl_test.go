package daemon

import (
	"fmt"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

// Postfix with dovecot SASL logs a failed SMTP AUTH as a smtpd warning that
// names the client but not the account. These are the formats rsyslog writes
// on Debian and RHEL hosts, including a submission service with its own
// syslog_name.
func TestPostfixSASLFailuresRaiseSMTPBruteForce(t *testing.T) {
	cases := []struct {
		name, format, ip string
	}{
		{"submission iso timestamp", "2026-10-31T12:34:11.494854+02:00 mail postfix/submission/smtpd[2207002]: warning: unknown[%s]: SASL LOGIN authentication failed: UGFzc3dvcmQ6", "203.0.113.50"},
		{"smtpd classic timestamp", "Oct 31 12:34:11 mail postfix/smtpd[1234]: warning: mx.example.net[%s]: SASL PLAIN authentication failed: ", "198.51.100.23"},
		{"ipv6 client", "Oct 31 12:34:11 mail postfix/submission/smtpd[99]: warning: unknown[%s]: SASL LOGIN authentication failed: authentication failure", "2001:db8::5"},
		{"no reply text", "Oct 31 12:34:11 mail postfix/smtpd[1234]: warning: unknown[%s]: SASL LOGIN authentication failed", "203.0.113.51"},
		{"client port logging", "Oct 31 12:34:11 mail postfix/smtpd[1234]: warning: unknown[%s]:51234: SASL LOGIN authentication failed: UGFzc3dvcmQ6", "203.0.113.52"},
		{"client port logging ipv6", "Oct 31 12:34:11 mail postfix/smtpd[1234]: warning: unknown[%s]:51234: SASL LOGIN authentication failed: UGFzc3dvcmQ6", "2001:db8::6"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			clock := &staticClock{t: time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)}
			d := New(&config.Config{}, nil, nil, "")
			d.smtpAuthTracker = newTestTracker(t, clock)
			var got []alert.Finding
			for i := 0; i < 5; i++ {
				got = append(got, d.handleMailLine(fmt.Sprintf(tc.format, tc.ip), alert.Observation{}, d.currentCfg())...)
			}
			if len(got) != 1 || got[0].Check != "smtp_bruteforce" || got[0].SourceIP != tc.ip {
				t.Fatalf("findings = %+v, want one smtp_bruteforce for %s after 5 failures", got, tc.ip)
			}
		})
	}
}

// Lines that look like SMTP AUTH failures but are not the client's fault, or
// do not come from postfix smtpd, must not count toward a block.
func TestPostfixSASLLinesThatMustNotCount(t *testing.T) {
	cases := []struct {
		name, line string
	}{
		{"auth server lost", "Oct 31 12:34:11 mail postfix/submission/smtpd[99]: warning: unknown[203.0.113.60]: SASL PLAIN authentication failed: Connection lost to authentication server"},
		{"auth server temporary failure", "Oct 31 12:34:11 mail postfix/submission/smtpd[99]: warning: unknown[203.0.113.61]: SASL PLAIN authentication failed: Temporary authentication failure"},
		{"other program", "Oct 31 12:34:11 mail dovecot: warning: unknown[203.0.113.62]: SASL LOGIN authentication failed: UGFzc3dvcmQ6"},
		{"postfix non-smtpd", "Oct 31 12:34:11 mail postfix/smtp[99]: warning: unknown[203.0.113.63]: SASL LOGIN authentication failed: UGFzc3dvcmQ6"},
		{"aborted by client", "Oct 31 12:34:11 mail postfix/smtpd[99]: warning: unknown[203.0.113.64]: SASL LOGIN authentication aborted"},
		{"infra address", "Oct 31 12:34:11 mail postfix/smtpd[99]: warning: unknown[192.0.2.10]: SASL LOGIN authentication failed: UGFzc3dvcmQ6"},
		{"private address", "Oct 31 12:34:11 mail postfix/smtpd[99]: warning: unknown[10.0.0.7]: SASL LOGIN authentication failed: UGFzc3dvcmQ6"},
		{"client field without brackets", "Oct 31 12:34:11 mail postfix/smtpd[99]: warning: 203.0.113.68x: SASL LOGIN authentication failed: UGFzc3dvcmQ6"},
		{"not an address", "Oct 31 12:34:11 mail postfix/smtpd[99]: warning: unknown[localhost]: SASL LOGIN authentication failed: UGFzc3dvcmQ6"},
		// smtpd echoes client-supplied text into other warnings; it must not
		// name an address of the client's choosing.
		{"client text in another warning", "Oct 31 12:34:11 mail postfix/smtpd[99]: warning: Illegal address syntax from unknown[203.0.113.65] in RCPT command: <x[198.51.100.9]: SASL LOGIN authentication failed: x>"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			clock := &staticClock{t: time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)}
			d := New(&config.Config{InfraIPs: []string{"192.0.2.10"}}, nil, nil, "")
			d.smtpAuthTracker = newTestTracker(t, clock)
			for i := 0; i < 10; i++ {
				if got := d.handleMailLine(tc.line, alert.Observation{}, d.currentCfg()); len(got) != 0 {
					t.Fatalf("findings = %+v, want none", got)
				}
			}
			if calls, _ := d.smtpAuthTracker.Stats(); calls != 0 {
				t.Fatalf("tracker recorded %d failures, want 0", calls)
			}
		})
	}
}

// The client address is the bracketed one that closes the client field, so
// a hostname carrying brackets cannot steer the block at another address.
func TestPostfixSASLFailureTracksTheClientAddress(t *testing.T) {
	clock := &staticClock{t: time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)}
	d := New(&config.Config{}, nil, nil, "")
	d.smtpAuthTracker = newTestTracker(t, clock)
	line := "Oct 31 12:34:11 mail postfix/smtpd[99]: warning: x[198.51.100.99].example[203.0.113.70]: SASL LOGIN authentication failed: UGFzc3dvcmQ6"
	var got []alert.Finding
	for i := 0; i < 5; i++ {
		got = append(got, d.handleMailLine(line, alert.Observation{}, d.currentCfg())...)
	}
	if len(got) != 1 || got[0].SourceIP != "203.0.113.70" {
		t.Fatalf("findings = %+v, want one finding for 203.0.113.70", got)
	}
}
