package eximlog

import (
	"net"
	"testing"
)

func TestClientIP(t *testing.T) {
	cases := []struct {
		name, line, want string
	}{
		{"h field client", "H=hostname [203.0.113.5]:12345", "203.0.113.5"},
		{"no brackets", "no brackets here", ""},
		{"bracketed hostname", "[hostname.example.com]", ""},
		{"short content", "[ab]", ""},
		{"unclosed bracket", "[203.0.113.5", ""},
		{"connection line without h field", "SMTP connection from [203.0.113.5]:12345", "203.0.113.5"},
		{"ipv6 without port", "from [2001:db8::1]", "2001:db8::1"},
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
			"x <= s@example.com H=hostname [203.0.113.5]:1234 for r@example.net T=[10.0.0.1]",
			"203.0.113.5",
		},
		{
			"h field spoofed inside subject",
			`2026-07-01 12:00:00 1abc-DEF-01 <= s@example.com T="Probe H=spoof [203.0.113.44]" for r@example.net`,
			"",
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
			`2026-04-14 12:00:00 dovecot_login authenticator failed for ([2001:db8::9]) [198.51.100.7]:5432: 535 Incorrect authentication data (set_id=alice@example.com)`,
			"198.51.100.7",
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

func FuzzClientIP(f *testing.F) {
	f.Add("H=client [203.0.113.50]:2222 auth failed")
	f.Add("no bracket here")
	f.Add("[1.2.3.4]")
	f.Add("[")
	f.Add("[unclosed bracket")
	f.Add("[][][][]")
	f.Add("authenticator failed for ([203.0.113.9]) [198.51.100.7]:5432: 535")
	f.Add("((( [1.2.3.4]")
	f.Fuzz(func(t *testing.T, line string) {
		got := ClientIP(line)
		if got != "" && net.ParseIP(got) == nil {
			t.Fatalf("ClientIP(%q) = %q, not a valid IP", line, got)
		}
	})
}
