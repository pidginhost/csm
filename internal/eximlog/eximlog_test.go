package eximlog

import (
	"testing"
)

func TestClientIP(t *testing.T) {
	cases := []struct {
		name, line, want string
	}{
		{"h field client", "H=hostname [203.0.113.5]:12345", "203.0.113.5"},
		{"h field before remote ident", "H=hostname [203.0.113.5]:12345 U=remote P=esmtp S=100", "203.0.113.5"},
		{"h field fast open", "H=hostname [203.0.113.5]:12345 TFO P=esmtp S=100", "203.0.113.5"},
		{"h field fast open data before remote ident", "H=hostname [203.0.113.5]:12345 TFO* U=remote P=esmtp S=100", "203.0.113.5"},
		{"h field interface before remote ident", "H=hostname [2001:db8::5]:12345 I=[192.0.2.25]:25 TFO* U=remote P=esmtp S=100", "2001:db8::5"},
		{"unprefixed peer before remote ident", "SMTP connection from hostname [203.0.113.5]:12345 U=remote", "203.0.113.5"},
		{"unprefixed interface before remote ident", "SMTP connection from hostname [2001:db8::5]:12345 I=[192.0.2.25]:25 U=remote", "2001:db8::5"},
		{"no brackets", "no brackets here", ""},
		{"bracketed hostname", "[hostname.example.com]", ""},
		{"short content", "[ab]", ""},
		{"unclosed bracket", "[203.0.113.5", ""},
		{"connection line without h field", "SMTP connection from [203.0.113.5]:12345", "203.0.113.5"},
		{"ipv6 bare TLS line", "TLS error on connection from [2001:db8::1]", "2001:db8::1"},
		{"ipv6 full", "H=mail.example.com [2001:db8:85a3::8a2e:370:7334]:25", "2001:db8:85a3::8a2e:370:7334"},
		{"ipv6 loopback", "H=localhost [::1]:25", "::1"},
		{
			"subject brackets ignored",
			`2026-07-01 12:00:00 1abc-DEF-01 <= sender@example.com H=mail.example.com (helo.example) [203.0.113.5]:41000 P=esmtpa A=dovecot_login:user@example.com S=1200 id=x@x T="Order [20260701-123] shipped" for rcpt@example.net`,
			"203.0.113.5",
		},
		{
			"bracketed helo text skipped",
			`2026-07-01 12:00:00 1abc-DEF-01 <= s@example.com H=nic.example (EHLO [not-an-ip]) [198.51.100.9]:2525 for r@example.net`,
			"198.51.100.9",
		},
		{
			"bracketed helo ip skipped",
			`2026-07-01 12:00:00 1abc-DEF-01 <= s@example.com H=nic.example (EHLO [10.0.0.1]) [198.51.100.9]:2525 P=esmtpsa for r@example.net`,
			"198.51.100.9",
		},
		{
			"h field without client does not fall back to subject",
			`2026-07-01 12:00:00 1abc-DEF-01 <= s@example.com H=nic.example P=esmtp T="Probe [203.0.113.44]" for r@example.net`,
			"",
		},
		{
			"h field client beats later bracketed token",
			`x <= s@example.com H=hostname [203.0.113.5]:1234 for r@example.net T="[10.0.0.1]"`,
			"203.0.113.5",
		},
		{
			"h field uses final client after junk helo",
			`x <= s@example.com H=(junk) [203.0.113.9]:25 (tail) [198.51.100.7]:5432 P=esmtpsa A=dovecot_login:user@example.com`,
			"198.51.100.7",
		},
		{
			"h field rejects junk helo that mimics a field boundary",
			`x <= s@example.com H=(junk) [203.0.113.9]:25 P=fake (tail) [198.51.100.7]:5432 P=esmtpsa A=dovecot_login:user@example.com`,
			"",
		},
		{
			"h field rejects ident marker inside junk helo",
			`H=(junk) [203.0.113.9]:25 U=fake (tail) [198.51.100.7]:5432 P=esmtp S=100`,
			"",
		},
		{
			"h field ignores logged local interface",
			`x <= s@example.com H=mail.example [198.51.100.7]:5432 I=[192.0.2.25]:25 P=esmtpsa A=dovecot_login:user@example.com`,
			"198.51.100.7",
		},
		{
			"h field spoofed inside subject",
			`2026-07-01 12:00:00 1abc-DEF-01 <= s@example.com T="Probe H=spoof [203.0.113.44]" for r@example.net`,
			"",
		},
		{
			"subject IP without h field ignored",
			`2026-07-01 12:00:00 1abc-DEF-01 <= local@example.com P=local T="Probe [203.0.113.44]" for r@example.net`,
			"",
		},
		{
			"connection marker inside subject ignored",
			`2026-07-01 12:00:00 1abc-DEF-01 <= local@example.com P=local T="SMTP connection from [203.0.113.44]:25" for r@example.net`,
			"",
		},
		{
			"h field before later failure text",
			`2026-04-14 10:00:01 H=client [203.0.113.50]:2222 authenticator failed for bad: 535 Auth failed`,
			"203.0.113.50",
		},
		// Exim writes the authenticator-failed line through host_and_ident(FALSE):
		// no H= field, attacker-chosen HELO in parentheses before the client.
		{
			"auth failure skips helo address literal",
			`2026-04-14 12:00:00 dovecot_login authenticator failed for ([203.0.113.9]) [198.51.100.7]:5432: 535 Incorrect authentication data (set_id=alice@example.com)`,
			"198.51.100.7",
		},
		{
			"auth failure with rdns skips helo address literal",
			`2026-04-14 12:00:00 dovecot_login authenticator failed for mail.example.net ([203.0.113.9]) [198.51.100.7]:5432: 535 Incorrect authentication data (set_id=alice@example.com)`,
			"198.51.100.7",
		},
		{
			"auth failure skips ipv6 helo literal",
			`2026-04-14 12:00:00 dovecot_login authenticator failed for ([IPv6:2001:db8::9]) [198.51.100.7]:5432: 535 Incorrect authentication data (set_id=alice@example.com)`,
			"198.51.100.7",
		},
		{
			"auth failure ignores h field text in junk helo",
			`2026-04-14 12:00:00 dovecot_login authenticator failed for (junk H=spoof [203.0.113.9]:25) [198.51.100.7]:5432: 535 Incorrect authentication data (set_id=alice@example.com)`,
			"198.51.100.7",
		},
		{
			"auth failure skips malformed bracket token",
			`2026-04-14 12:00:00 dovecot_login authenticator failed for bad[203.0.113.9]suffix [198.51.100.7]:5432: 535 Incorrect authentication data (set_id=alice@example.com)`,
			"198.51.100.7",
		},
		{
			"auth failure ignores logged local interface",
			`2026-04-14 12:00:00 dovecot_login authenticator failed for (mail.example) [198.51.100.7]:5432 I=[192.0.2.25]:25: 535 Incorrect authentication data`,
			"198.51.100.7",
		},
		{
			"auth failure rejects ambiguous junk helo",
			`2026-04-14 12:00:00 dovecot_login authenticator failed for (junk) [203.0.113.9]:25 (tail) [198.51.100.7]:5432: 535 Incorrect authentication data`,
			"",
		},
		{
			"auth failure rejects unmatched junk helo close",
			`2026-04-14 12:00:00 dovecot_login authenticator failed for (junk) [203.0.113.9]:25) [198.51.100.7]:5432: 535 Incorrect authentication data`,
			"",
		},
		{
			"tls error skips helo address literal",
			`2026-04-14 12:00:00 TLS error on connection from ([203.0.113.9]) [198.51.100.7]:5432 (SSL_accept): error:0A000126:SSL routines::unexpected eof while reading`,
			"198.51.100.7",
		},
		{
			"unclosed helo literal yields nothing rather than the helo",
			`authenticator failed for ([203.0.113.9) [198.51.100.7]:5432: 535`,
			"",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := ClientIP(c.line); got != c.want {
				t.Errorf("ClientIP(%q) = %q, want %q", c.line, got, c.want)
			}
		})
	}
}

func TestHFieldClientIPAndEndSkipsWholeHValue(t *testing.T) {
	s := `nic.example (EHLO [10.0.0.1]) [198.51.100.9]:2525 P=esmtpsa for r@example.net`
	ip, end := HFieldClientIPAndEnd(s)
	if ip != "198.51.100.9" {
		t.Fatalf("ip = %q, want 198.51.100.9", ip)
	}
	if got := s[end:]; got != ":2525 P=esmtpsa for r@example.net" {
		t.Fatalf("rest after client = %q", got)
	}
}

func TestHFieldClientIPAndEndStopsAtNextField(t *testing.T) {
	if ip, end := HFieldClientIPAndEnd(`nic.example P=esmtp T="Probe [203.0.113.44]"`); ip != "" || end != 0 {
		t.Fatalf("got (%q, %d), want empty", ip, end)
	}
}

// A remote ident marker before the chosen peer shows that greeting
// delimiters hid the real peer. Peer-like text after the chosen peer is
// message data and is covered by TestFailureDetailsCannotHidePeer.
func TestHFieldClientIPAndEndRejectsPeerInIdent(t *testing.T) {
	for _, s := range []string{
		`(hello() [203.0.113.5]:2525 U=) [192.0.2.8] P=esmtp S=100`,
		`(hello) ") [203.0.113.5]:2525 U=" [192.0.2.8] P=esmtp S=100`,
		`(hello[) [203.0.113.5]:2525 U=) [192.0.2.8] P=esmtp S=100`,
	} {
		if ip, end := HFieldClientIPAndEnd(s); ip != "" || end != 0 {
			t.Errorf("peer inside remote ident accepted: (%q, %d)", ip, end)
		}
		if ip := ClientIP("H=" + s); ip != "" {
			t.Errorf("ClientIP accepted peer inside remote ident: %q", ip)
		}
	}
}

func TestClientIPRejectsPeerInUnprefixedIdent(t *testing.T) {
	for _, marker := range []string{
		"dovecot_login authenticator failed for ",
		"TLS error on connection from ",
		"SMTP connection from ",
	} {
		for _, peer := range []string{
			`(hello() [203.0.113.5]:2525 U=) [192.0.2.8]`,
			`(hello) ") [203.0.113.5]:2525 U=" [192.0.2.8]`,
			`(hello[) [203.0.113.5]:2525 U=) [192.0.2.8]`,
		} {
			if ip := ClientIP(marker + peer + ": connection rejected"); ip != "" {
				t.Errorf("ClientIP(%q) accepted peer inside remote ident: %q", marker+peer, ip)
			}
		}
	}
}
