package checks

import (
	"testing"

	"github.com/pidginhost/csm/internal/config"
)

// Exim logs the attacker-chosen HELO in parentheses before the connecting
// client. A HELO may be an RFC 5321 address literal, so the first bracketed
// IP on the line is not necessarily the client; reputation candidates must
// come from the real peer or an attacker can point lookups (and any block
// that follows) at an address of their choosing.
func TestCollectRecentIPsEximAuthFailureIgnoresHELOAddressLiteral(t *testing.T) {
	forceCPanelPlatform(t)
	content := "2026-04-14 10:00:00 dovecot_login authenticator failed for ([203.0.113.9]) [198.51.100.7]:5432: 535 Incorrect authentication data (set_id=alice@example.com)\n" +
		"2026-04-14 10:00:01 H=([203.0.113.9]) [198.51.100.8]:1234 F=<spam@example.net> rejected RCPT <victim@example.org>: relay not permitted\n"
	withMockOS(t, writeMockLog(t, "/var/log/exim_mainlog", content))

	ips := collectRecentIPs(&config.Config{})
	if _, forged := ips["203.0.113.9"]; forged {
		t.Errorf("HELO address literal 203.0.113.9 must not become a reputation candidate (full map %v)", ips)
	}
	if src := ips["198.51.100.7"]; src != "SMTP auth failure" {
		t.Errorf("auth-failure client 198.51.100.7: got source %q, want SMTP auth failure (full map %v)", src, ips)
	}
	if src := ips["198.51.100.8"]; src != "SMTP auth failure" {
		t.Errorf("rejected-RCPT client 198.51.100.8: got source %q, want SMTP auth failure (full map %v)", src, ips)
	}
}

// Subjects and greetings are client text. Failure wording there must not
// make an arrival's sender, or an address named in that text, a reputation
// candidate; a real authentication failure record still does.
func TestCollectRecentIPsEximAuthFailureNeedsRecord(t *testing.T) {
	forceCPanelPlatform(t)
	const fake = "dovecot_login authenticator failed for [192.0.2.9]: 535 Incorrect authentication data (set_id=b@example.com)"
	content := `2026-04-14 10:00:00 1abc-DEF-01 <= a@example.com H=mail.example.com [203.0.113.42]:54321 P=esmtp S=1234 T="` + fake + `"` + "\n" +
		`2026-04-14 10:00:01 1abc-DEF-02 <= a@example.com H=(` + fake + `) [203.0.113.43]:54321 P=esmtp S=1234` + "\n" +
		"2026-04-14 10:00:02 dovecot_login authenticator failed for (mail.example.com) [198.51.100.7]:5432: 535 Incorrect authentication data (set_id=alice@example.com)\n"
	withMockOS(t, writeMockLog(t, "/var/log/exim_mainlog", content))

	ips := collectRecentIPs(&config.Config{})
	for _, ip := range []string{"203.0.113.42", "203.0.113.43", "192.0.2.9"} {
		if src, ok := ips[ip]; ok {
			t.Errorf("client text made %s a candidate (%q); full map %v", ip, src, ips)
		}
	}
	if src := ips["198.51.100.7"]; src != "SMTP auth failure" {
		t.Errorf("auth-failure client 198.51.100.7: got source %q, want SMTP auth failure (full map %v)", src, ips)
	}
}
