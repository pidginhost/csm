package mailstats

import (
	"strings"
	"testing"
)

const (
	pfSMTPD      = "2026-10-20T12:00:00.123456+00:00 mx postfix/smtpd[1234]: "
	pfSubmission = "2026-10-20T12:00:00.123456+00:00 mx postfix/submission/smtpd[9]: "
	pfPostscreen = "2026-10-20T12:00:00.123456+00:00 mx postfix/postscreen[77]: "
	pfCleanup    = "2026-10-20T12:00:00.123456+00:00 mx postfix/cleanup[55]: "
	pfTail       = "; from=<a@example.net> to=<u@example.com> proto=ESMTP helo=<mail.example.net>"
	pfUnknown    = "NOQUEUE: reject: RCPT from unknown[192.0.2.10]: 550 5.1.1 <nobody@example.com>: Recipient address rejected: undeliverable address: host mx.example.com[private/dovecot-lmtp] said: 550 5.1.1 <nobody@example.com> User doesn't exist: nobody@example.com (in reply to RCPT TO command); from=<a@example.net> to=<nobody@example.com> proto=ESMTP helo=<mail.example.net>"
)

var postfixRejectCases = []struct {
	name                         string
	line                         string
	class                        Class
	temporary                    bool
	ip, sender, recipient, msgID string
	command, detail              string
}{
	{"unknown recipient via lmtp probe", pfSMTPD + pfUnknown,
		ClassUnknownRecipient, false, "192.0.2.10", "a@example.net", "nobody@example.com", "", "RCPT",
		"<nobody@example.com>: Recipient address rejected: undeliverable address"},
	{"unknown recipient in table", pfSMTPD + "NOQUEUE: reject: RCPT from mx.example.net[192.0.2.11]: 550 5.1.1 <nobody@example.com>: Recipient address rejected: User unknown in virtual mailbox table" + pfTail,
		ClassUnknownRecipient, false, "192.0.2.11", "a@example.net", "u@example.com", "", "RCPT",
		"<nobody@example.com>: Recipient address rejected: User unknown"},
	{"sender domain not found", pfSMTPD + "NOQUEUE: reject: RCPT from unknown[192.0.2.12]: 450 4.1.8 <a@nx.example.net>: Sender address rejected: Domain not found; from=<a@nx.example.net> to=<u@example.com> proto=ESMTP helo=<x>",
		ClassSenderVerify, true, "192.0.2.12", "a@nx.example.net", "u@example.com", "", "RCPT",
		"<a@nx.example.net>: Sender address rejected: Domain not found"},
	{"postscreen blocklist", pfPostscreen + "NOQUEUE: reject: RCPT from [198.51.100.7]:50416: 550 5.7.1 Service unavailable; client [198.51.100.7] blocked using zen.example.org; from=<a@example.net>, to=<u@example.com>, proto=ESMTP, helo=<x>",
		ClassBlocklisted, false, "198.51.100.7", "a@example.net", "u@example.com", "", "RCPT",
		"Service unavailable; client [198.51.100.7] blocked using zen.example.org"},
	{"smtpd blocklist", pfSMTPD + "NOQUEUE: reject: RCPT from unknown[203.0.113.9]: 554 5.7.1 Service unavailable; Client host [203.0.113.9] blocked using bl.example.org; listed for testing" + pfTail,
		ClassBlocklisted, false, "203.0.113.9", "a@example.net", "u@example.com", "", "RCPT",
		"Service unavailable; Client host [203.0.113.9] blocked using bl.example.org"},
	{"client access denied", pfSubmission + "NOQUEUE: reject: RCPT from mail.example.net[203.0.113.9]: 554 5.7.1 <mail.example.net[203.0.113.9]>: Client host rejected: Access denied" + pfTail,
		ClassOther, false, "203.0.113.9", "a@example.net", "u@example.com", "", "RCPT",
		"<mail.example.net[203.0.113.9]>: Client host rejected: Access denied"},
	{"relay denied", pfSMTPD + "NOQUEUE: reject: RCPT from unknown[192.0.2.13]: 554 5.7.1 <u@example.org>: Relay access denied" + pfTail,
		ClassRelayDenied, false, "192.0.2.13", "a@example.net", "u@example.com", "", "RCPT",
		"<u@example.org>: Relay access denied"},
	{"bad helo", pfSMTPD + "NOQUEUE: reject: RCPT from unknown[192.0.2.14]: 504 5.5.2 <localhost>: Helo command rejected: need fully-qualified hostname" + pfTail,
		ClassBadHELO, false, "192.0.2.14", "a@example.net", "u@example.com", "", "RCPT",
		"<localhost>: Helo command rejected"},
	{"submission service", pfSubmission + pfUnknown,
		ClassUnknownRecipient, false, "192.0.2.10", "a@example.net", "nobody@example.com", "", "RCPT", "<nobody@example.com>"},
	{"milter spam over ipv6", pfCleanup + "4F1A2B3C4D: milter-reject: END-OF-MESSAGE from mail.example.net[2001:db8::1]: 5.7.1 Spam message rejected" + pfTail,
		ClassSpam, false, "2001:db8::1", "a@example.net", "u@example.com", "4F1A2B3C4D", "", "Spam message rejected"},
	{"milter malware", pfCleanup + `4F1A2B3C4E: milter-reject: END-OF-MESSAGE from h.example.net[192.0.2.4]: 5.7.1 clamav: virus found: "Example-Test-Signature"` + pfTail,
		ClassMalware, false, "192.0.2.4", "a@example.net", "u@example.com", "4F1A2B3C4E", "", "clamav: virus found"},
	{"milter temporary", pfCleanup + "4F1A2B3C4F: milter-reject: END-OF-MESSAGE from h.example.net[192.0.2.4]: 4.7.1 Try again later" + pfTail,
		ClassOther, true, "192.0.2.4", "a@example.net", "u@example.com", "4F1A2B3C4F", "", "Try again later"},
	{"syslog stamp", "Oct 20 12:00:00 mx postfix/smtpd[1]: " + pfUnknown,
		ClassUnknownRecipient, false, "192.0.2.10", "a@example.net", "nobody@example.com", "", "RCPT", "<nobody@example.com>"},
	// A client must not choose the class of its own reject.
	{"quoted recipient posing as a sender reject", pfSMTPD + `NOQUEUE: reject: RCPT from unknown[192.0.2.15]: 550 5.1.1 <"x>: Sender address rejected: y"@example.com>: Recipient address rejected: User unknown in virtual mailbox table` + pfTail,
		ClassOther, false, "192.0.2.15", "a@example.net", "u@example.com", "", "RCPT", `<"x>: Sender address rejected`},
	// The recipient is logged unquoted inside the reply, so it can hold reason
	// text. Conflicting possible boundaries must stay unclassified.
	{"spaced recipient posing as a blocklist reject", pfSMTPD + "NOQUEUE: reject: RCPT from unknown[192.0.2.15]: 550 5.1.1 <x>: Service unavailable; client [192.0.2.15] blocked using z@example.com>: Recipient address rejected: User unknown in virtual mailbox table" + pfTail,
		ClassOther, false, "192.0.2.15", "a@example.net", "u@example.com", "", "RCPT", "<x>: Service unavailable"},
	{"spaced recipient posing as a sender reject", pfSMTPD + "NOQUEUE: reject: RCPT from unknown[192.0.2.15]: 550 5.1.1 <x>: Sender address rejected: Domain not found@example.com>: Recipient address rejected: User unknown in virtual mailbox table" + pfTail,
		ClassOther, false, "192.0.2.15", "a@example.net", "u@example.com", "", "RCPT", "<x>: Sender address rejected"},
	// A recipient holding the envelope marker must not cut Postfix's reason
	// off and leave its own text as the only one.
	{"recipient posing as the envelope", pfSMTPD + `NOQUEUE: reject: RCPT from unknown[192.0.2.16]: 550 5.1.1 <x>: Sender address rejected: y; from=<q@example.org>: Recipient address rejected: User unknown in virtual mailbox table; from=<a@example.net> to=<"x>: Sender address rejected: y; from=<q"@example.org> proto=ESMTP helo=<h>`,
		ClassOther, false, "192.0.2.16", "a@example.net", `"x>: Sender address rejected: y; from=<q"@example.org`, "", "RCPT", "<x>: Sender address rejected"},
	{"backend reply repeating the reason", pfSMTPD + "NOQUEUE: reject: RCPT from unknown[192.0.2.17]: 550 5.1.1 <nobody@example.com>: Recipient address rejected: undeliverable address: host backend.example.com[192.0.2.99] said: 550 5.1.1 <nobody@example.com>: Recipient address rejected: User unknown in local recipient table (in reply to RCPT TO command)" + pfTail,
		ClassUnknownRecipient, false, "192.0.2.17", "a@example.net", "u@example.com", "", "RCPT", "<nobody@example.com>"},
	{"recipient refused by policy", pfSMTPD + "NOQUEUE: reject: RCPT from unknown[192.0.2.18]: 554 5.7.1 <u@example.com>: Recipient address rejected: Access denied" + pfTail,
		ClassOther, false, "192.0.2.18", "a@example.net", "u@example.com", "", "RCPT", "<u@example.com>: Recipient address rejected: Access denied"},
	{"sender blocklisted", pfSMTPD + "NOQUEUE: reject: RCPT from unknown[192.0.2.19]: 554 5.7.1 Service unavailable; Sender address [a@example.net] blocked using dbl.example.org" + pfTail,
		ClassBlocklisted, false, "192.0.2.19", "a@example.net", "u@example.com", "", "RCPT", "Service unavailable; Sender address"},
}

func TestParsePostfixReject(t *testing.T) {
	for _, c := range postfixRejectCases {
		t.Run(c.name, func(t *testing.T) {
			r, ok := ParsePostfixReject(c.line, rejectLoc, rejectFallback)
			if !ok {
				t.Fatalf("not parsed: %s", c.line)
			}
			if r.Class != c.class || r.Temporary != c.temporary {
				t.Errorf("class %q temporary %v, want %q %v", r.Class, r.Temporary, c.class, c.temporary)
			}
			if r.IP != c.ip || r.Sender != c.sender || r.Recipient != c.recipient || r.MsgID != c.msgID || r.Command != c.command {
				t.Errorf("ip %q sender %q recipient %q msgID %q command %q, want %q %q %q %q %q",
					r.IP, r.Sender, r.Recipient, r.MsgID, r.Command, c.ip, c.sender, c.recipient, c.msgID, c.command)
			}
			if !strings.HasPrefix(r.Detail, c.detail) {
				t.Errorf("detail %q, want prefix %q", r.Detail, c.detail)
			}
			if got := r.At.UTC().Format("2006-01-02 15:04:05"); got != "2026-10-20 12:00:00" {
				t.Errorf("at %s, want 2026-10-20 12:00:00", got)
			}
		})
	}
}

func TestParsePostfixRejectIgnoresOtherLines(t *testing.T) {
	for name, line := range map[string]string{
		"connect":              pfSMTPD + "connect from unknown[192.0.2.10]",
		"accepted":             pfSMTPD + "4F1A2B3C4D: client=unknown[192.0.2.10]",
		"other program":        "2026-10-20T12:00:00.123456+00:00 mx dovecot: lmtp(1): " + pfUnknown,
		"other postfix daemon": "2026-10-20T12:00:00.123456+00:00 mx postfix/qmgr[1]: " + pfUnknown,
		"tag without pid":      "2026-10-20T12:00:00.123456+00:00 mx postfix/smtpd: " + pfUnknown,
		"reject echoed later":  pfSMTPD + "warning: header Subject: " + pfUnknown,
		"spaced client":        pfSMTPD + "NOQUEUE: reject: RCPT from evil host[192.0.2.1]: 550 5.1.1 <u@example.com>: Recipient address rejected: User unknown" + pfTail,
		"client without ip":    pfSMTPD + "NOQUEUE: reject: RCPT from host[not-an-ip]: 550 5.1.1 <u@example.com>: Recipient address rejected: User unknown" + pfTail,
		"bad queue id":         pfCleanup + "NO-QUEUE!: milter-reject: END-OF-MESSAGE from h[192.0.2.4]: 5.7.1 Spam message rejected" + pfTail,
		"lower case command":   pfSMTPD + "NOQUEUE: reject: rcpt from unknown[192.0.2.10]: 550 5.1.1 <u@example.com>: Recipient address rejected: User unknown" + pfTail,
		"empty":                "",
	} {
		if r, ok := ParsePostfixReject(line, rejectLoc, rejectFallback); ok {
			t.Errorf("%s: parsed as %+v", name, r)
		}
	}
}

func TestPostfixRejectClientTextCannotChooseClass(t *testing.T) {
	for name, reply := range map[string]string{
		"unknown policy after fake sender reason":  "<x>: Sender address rejected: y@example.com>: Address rejected: Access denied",
		"fake mailbox reason after policy refusal": "<x>: Recipient address rejected: User unknown@example.com>: Recipient address rejected: Access denied",
		"fake reason in backend address":           "<u@example.com>: Recipient address rejected: Access denied: <x>: Recipient address rejected: User unknown@example.net>",
	} {
		t.Run(name, func(t *testing.T) {
			line := pfSMTPD + "NOQUEUE: reject: RCPT from unknown[192.0.2.10]: 550 5.1.1 " + reply + pfTail
			r, ok := ParsePostfixReject(line, rejectLoc, rejectFallback)
			if !ok || r.Class != ClassOther {
				t.Fatalf("got %+v, parsed %v; want other", r, ok)
			}
		})
	}
	for _, payload := range []string{
		"x>: Sender address rejected: Domain not found; from=<y@example.net",
		"x>: Recipient address rejected: User unknown; from=<y@example.net",
		"x: virus found: y; from=<z@example.net",
		"x blocked using bl.example.org; from=<y@example.net",
	} {
		for name, reply := range map[string]string{
			"named policy":   "<u@example.com>: Address rejected: Access denied",
			"service policy": "Service unavailable; Access denied",
			"milter policy":  "Message refused by policy",
		} {
			prefix := pfSMTPD + "NOQUEUE: reject: RCPT"
			if name == "milter policy" {
				prefix = pfCleanup + "ABC123: milter-reject: END-OF-MESSAGE"
			}
			line := prefix + " from unknown[192.0.2.10]: 550 5.7.1 " + reply + strings.TrimSuffix(pfTail, "mail.example.net>") + payload + ">"
			r, ok := ParsePostfixReject(line, rejectLoc, rejectFallback)
			if !ok || r.Class != ClassOther {
				t.Errorf("%s with HELO %q: got %+v, parsed %v; want other", name, payload, r, ok)
			}
		}
	}
}

func TestPostfixRejectNamedClientBlocklist(t *testing.T) {
	line := pfSMTPD + "NOQUEUE: reject: RCPT from unknown[192.0.2.10]: 554 5.7.1 <unknown[192.0.2.10]>: Client host rejected: blocked using bl.example.org" + pfTail
	r, ok := ParsePostfixReject(line, rejectLoc, rejectFallback)
	if !ok || r.Class != ClassBlocklisted {
		t.Fatalf("got %+v, parsed %v; want blocklisted", r, ok)
	}
}

func TestPostfixRejectQuotedEnvelope(t *testing.T) {
	line := pfSMTPD + `NOQUEUE: reject: RCPT from unknown[192.0.2.10]: 550 5.7.1 Access denied; from=<"a>b"@example.net> to=<"c>d"@example.com> proto=ESMTP helo=<mail.example.net>`
	r, ok := ParsePostfixReject(line, rejectLoc, rejectFallback)
	if !ok || r.Sender != `"a>b"@example.net` || r.Recipient != `"c>d"@example.com` {
		t.Fatalf("got %+v, parsed %v; want intact quoted envelope addresses", r, ok)
	}
}

func TestPostfixRejectAmbiguousEnvelope(t *testing.T) {
	line := pfSMTPD + "NOQUEUE: reject: RCPT from unknown[192.0.2.10]: 550 5.7.1 Access denied" + pfTail + "; from=<b@example.org> to=<c@example.com> proto=ESMTP helo=<mail.example.org>"
	r, ok := ParsePostfixReject(line, rejectLoc, rejectFallback)
	if !ok || r.Class != ClassOther || r.Sender != "" || r.Recipient != "" {
		t.Fatalf("got %+v, parsed %v; want other with no ambiguous addresses", r, ok)
	}
}

func TestPostfixRejectBeforeMailIgnoresHELO(t *testing.T) {
	for _, tc := range []struct {
		message string
		class   Class
	}{
		{"NOQUEUE: milter-reject: EHLO from unknown[192.0.2.10]: 550 5.7.1 Message refused by policy; proto=ESMTP helo=<x: virus found: y>", ClassOther},
		{"NOQUEUE: reject: EHLO from unknown[192.0.2.10]: 550 5.7.1 Service unavailable; proto=ESMTP helo=<x blocked using bl.example.org>", ClassOther},
		{"NOQUEUE: milter-reject: EHLO from unknown[192.0.2.10]: 550 5.7.1 Spam message rejected; proto=ESMTP helo=<mail.example.net>", ClassSpam},
	} {
		r, ok := ParsePostfixReject(pfSMTPD+tc.message, rejectLoc, rejectFallback)
		if !ok || r.Class != tc.class {
			t.Errorf("got %+v, parsed %v; want %s", r, ok, tc.class)
		}
	}
}
