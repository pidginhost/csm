package mailstats

import (
	"strings"
	"testing"
	"time"
)

var (
	rejectLoc      = time.UTC
	rejectFallback = time.Date(2026, 10, 20, 12, 5, 0, 0, time.UTC)
)

var rejectClassCases = []struct {
	line                         string
	class                        Class
	temporary                    bool
	ip, sender, recipient, msgID string
}{
	{"2026-10-20 12:00:00 1tAbCd-000001-Ab H=mx.example.net [203.0.113.5]:52341 X=TLS1.3:TLS_AES_256_GCM_SHA384:256 F=<prefix=a@example.com> rejected after DATA: 550 5.7.1 Message rejected as spam",
		ClassSpam, false, "203.0.113.5", "prefix=a@example.com", "", "1tAbCd-000001-Ab"},
	{"2026-10-20 12:00:00 1tAbCd-000002-Ab H=(mx.example.net) [203.0.113.5]:52341 F=<a@example.com> rejected after DATA: Message rejected as spam",
		ClassSpam, false, "203.0.113.5", "a@example.com", "", "1tAbCd-000002-Ab"},
	{"2026-10-20 12:00:00 1tAbCd-000003-Ab H=(helo.example.net) [203.0.113.6]:1943 X=TLS1.3:TLS_AES_256_GCM_SHA384:256 F=<a@example.com> rejected after DATA: This message contains a virus or other harmful content (Example.Test-1)",
		ClassMalware, false, "203.0.113.6", "a@example.com", "", "1tAbCd-000003-Ab"},
	{"2026-10-20 12:00:00 H=mx.example.net (helo.example.net) [203.0.113.7]:2445 F=<a@example.com> rejected RCPT <b@example.net>: No Such User Here",
		ClassUnknownRecipient, false, "203.0.113.7", "a@example.com", "b@example.net", ""},
	{`2026-10-20 12:00:00 H=mail.example.net (helo.example.net) [203.0.113.8]:61216 F=<> rejected RCPT <b@example.net>: No Such User Here"`,
		ClassUnknownRecipient, false, "203.0.113.8", "", "b@example.net", ""},
	{"2026-10-20 12:00:00 H=(helo.example.net) [198.51.100.1]:4000 F=<a@example.com> rejected RCPT <b@example.net>: No such person at this address",
		ClassUnknownRecipient, false, "198.51.100.1", "a@example.com", "b@example.net", ""},
	{"2026-10-20 12:00:00 H=mx.example.net (helo.example.net) [198.51.100.2]:26463 F=<a@example.com> rejected RCPT <b@example.net>: The mail server could not deliver mail to c@example.net  The account or domain may not exist, they may be blacklisted, or missing the proper dns entries.",
		ClassUnknownRecipient, false, "198.51.100.2", "a@example.com", "b@example.net", ""},
	{"2026-10-20 12:00:00 H=(helo.example.net) [198.51.100.3]:56548 F=<a@example.com> rejected RCPT <b@example.net>: Sender verify failed",
		ClassSenderVerify, false, "198.51.100.3", "a@example.com", "b@example.net", ""},
	{"2026-10-20 12:00:00 H=mx.example.net (helo.example.net) [198.51.100.4]:47782 F=<a@example.com> temporarily rejected RCPT <b@example.net>: Could not complete sender verify",
		ClassSenderVerify, true, "198.51.100.4", "a@example.com", "b@example.net", ""},
	{"2026-10-20 12:00:00 H=(WORKSTATION-1) [203.0.113.9]:54793 rejected MAIL <a@example.com>: Access denied - Invalid HELO name (See RFC2821 192.0.2.25)",
		ClassBadHELO, false, "203.0.113.9", "a@example.com", "", ""},
	{"2026-10-20 12:00:00 H=(WORKSTATION-2) [203.0.113.9]:60207 rejected MAIL <>: Access denied - Invalid HELO name (See RFC2821 192.0.2.25)",
		ClassBadHELO, false, "203.0.113.9", "", "", ""},
	{"2026-10-20 12:00:00 H=(helo.example.net) [203.0.113.10]:56878 F=<a@example.com> rejected RCPT <b@example.net>: Rejected relay attempt: '203.0.113.10' From: 'a@example.com' To: 'b@example.net'",
		ClassRelayDenied, false, "203.0.113.10", "a@example.com", "b@example.net", ""},
	{"2026-10-20 12:00:00 H=(helo.example.net) [203.0.113.10]:56879 F=<a@example.com> rejected RCPT <b@example.net>: relay not permitted",
		ClassRelayDenied, false, "203.0.113.10", "a@example.com", "b@example.net", ""},
	{"2026-10-20 12:00:00 H=([203.0.113.11]) [203.0.113.12]:48658 X=TLS1.3:TLS_AES_256_GCM_SHA384:256 F=<a@example.com> rejected RCPT <b@example.net>: SMTP AUTH is required for message submission on port 465",
		ClassAuthRequired, false, "203.0.113.12", "a@example.com", "b@example.net", ""},
	{`2026-10-20 12:00:00 H=(helo.example.net) [203.0.113.13]:37252 F=<a@example.com> rejected RCPT <b@example.net>: Outgoing mail from "a.example.com" has been suspended.`,
		ClassSuspended, false, "203.0.113.13", "a@example.com", "b@example.net", ""},
	{"2026-10-20 12:00:00 H=mx.example.net [203.0.113.14]:33709 X=TLS1.2:ECDHE-RSA-AES256-GCM-SHA384:256 F=<a@example.com> rejected RCPT <b@example.net>: Mail to b@example.net has been suspended",
		ClassSuspended, false, "203.0.113.14", "a@example.com", "b@example.net", ""},
	{"2026-10-20 12:00:00 H=mx.example.net [203.0.113.15]:37845 X=TLS1.3:TLS_AES_256_GCM_SHA384:256 F=<a@example.com> rejected RCPT <b@example.net>: Mailbox is full / Blocks limit exceeded / Inode limit exceeded",
		ClassMailboxFull, false, "203.0.113.15", "a@example.com", "b@example.net", ""},
	{"2026-10-20 12:00:00 H=mx.example.net (helo.example.net) [203.0.113.16]:2525 F=<a@example.com> rejected RCPT <b@example.net>: JunkMail rejected - mx.example.net (helo.example.net) [203.0.113.16]:2525 is in an RBL: Error: open resolver",
		ClassBlocklisted, false, "203.0.113.16", "a@example.com", "b@example.net", ""},
	{`2026-10-20 12:00:00 H=[203.0.113.17]:2526 rejected connection in "connect" ACL: "203.0.113.17 is listed at bl.example.net"`,
		ClassBlocklisted, false, "203.0.113.17", "", "", ""},
	{`2026-10-20 12:00:00 H=mx.example.net [198.51.100.9]:11232 temporarily rejected connection in "connect" ACL: "Host is ratelimited (x)"`,
		ClassRateLimited, true, "198.51.100.9", "", "", ""},
	{`2026-10-20 12:00:00 H=[198.51.100.10]:54115 temporarily rejected connection in "connect" ACL: "Host is ratelimited due to multiple failure only connections (x)"`,
		ClassRateLimited, true, "198.51.100.10", "", "", ""},
	{`2026-10-20 12:00:00 H=[2001:db8::5]:40000 temporarily rejected connection in "connect" ACL: "Host is ratelimited (x)"`,
		ClassRateLimited, true, "2001:db8::5", "", "", ""},
	// Exim logs the authenticator and login after an authenticated sender.
	{`2026-10-20 12:00:00 H=(x.example.net) [203.0.113.18]:5 F=<a@example.com> A=dovecot_login:a@example.com rejected RCPT <b@example.net>: Outgoing mail from "x.example.net" has been suspended.`,
		ClassSuspended, false, "203.0.113.18", "a@example.com", "b@example.net", ""},
	{"2026-10-20 12:00:00 1tAbCd-000004-Ab H=(x.example.net) [203.0.113.19]:587 X=TLS1.3:TLS_AES_256_GCM_SHA384:256 F=<a@example.com> A=dovecot_plain:a@example.com rejected after DATA: 550 5.7.1 Message rejected as spam",
		ClassSpam, false, "203.0.113.19", "a@example.com", "", "1tAbCd-000004-Ab"},
	{"2026-10-20 12:00:00 H=(x.example.net) [203.0.113.20]:587 F=<a@example.com> A=dovecot_login:a@example.com temporarily rejected RCPT <b@example.net>: Could not complete sender verify",
		ClassSenderVerify, true, "203.0.113.20", "a@example.com", "b@example.net", ""},
	// A rate-limit text on a permanent reject is not this class.
	{"2026-10-20 12:00:00 H=(helo.example.net) [198.51.100.11]:4001 F=<a@example.com> rejected RCPT <b@example.net>: Host is ratelimited (x)",
		ClassOther, false, "198.51.100.11", "a@example.com", "b@example.net", ""},
	{"2026-10-20 12:00:00 H=(helo.example.net) [198.51.100.12]:5541 F=<a@example.com> rejected RCPT <b@example.net>: Example unlisted reason",
		ClassOther, false, "198.51.100.12", "a@example.com", "b@example.net", ""},
	{"2026-10-20 12:00:00 H=(helo.example.net) [198.51.100.13]:58592 F=<> rejected RCPT <b@example.net>: ",
		ClassOther, false, "198.51.100.13", "", "b@example.net", ""},
	{`2026-10-20 12:00:00 H=(helo.example.net) [198.51.100.14]:55024 F=<a@example.com> rejected RCPT <b@example.net>: "`,
		ClassOther, false, "198.51.100.14", "a@example.com", "b@example.net", ""},
	{"2026-10-20 12:00:00 H=(helo.example.net) [198.51.100.15]:4002 rejected EHLO or HELO helo.example.net: Example reason",
		ClassOther, false, "198.51.100.15", "", "", ""},
	{"2026-10-20 12:00:00 H=(helo.example.net) [198.51.100.16]:4003 F=<a@example.com> temporarily rejected VRFY b@example.net: Example reason",
		ClassOther, true, "198.51.100.16", "a@example.com", "", ""},
}

func TestParseRejectClasses(t *testing.T) {
	at := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	for _, c := range rejectClassCases {
		r, ok := ParseReject(c.line, rejectLoc, rejectFallback)
		if !ok {
			t.Errorf("not parsed: %s", c.line)
			continue
		}
		if r.Class != c.class || r.Temporary != c.temporary || r.IP != c.ip ||
			r.Sender != c.sender || r.Recipient != c.recipient || r.MsgID != c.msgID {
			t.Errorf("%s\n got class=%q temp=%v ip=%q sender=%q rcpt=%q id=%q\nwant class=%q temp=%v ip=%q sender=%q rcpt=%q id=%q",
				c.line, r.Class, r.Temporary, r.IP, r.Sender, r.Recipient, r.MsgID,
				c.class, c.temporary, c.ip, c.sender, c.recipient, c.msgID)
		}
		if !r.At.Equal(at) {
			t.Errorf("%s: at = %v, want %v", c.line, r.At, at)
		}
	}
}

func TestParseRejectDetail(t *testing.T) {
	cases := []struct{ line, want string }{
		{"2026-10-20 12:00:00 1tAbCd-000001-Ab H=mx.example.net [203.0.113.5]:1 F=<a@example.com> rejected after DATA: 550 5.7.1 Message rejected as spam",
			"Message rejected as spam"},
		{"2026-10-20 12:00:00 H=mx.example.net [203.0.113.5]:1 F=<a@example.com> temporarily rejected RCPT <b@example.net>: 451 Could not complete sender verify",
			"Could not complete sender verify"},
		{"2026-10-20 12:00:00 H=mx.example.net [203.0.113.5]:1 F=<a@example.com> rejected RCPT <b@example.net>: No Such\x01 User Here\x7f",
			"No Such User Here"},
		{"2026-10-20 12:00:00 H=mx.example.net [203.0.113.5]:1 F=<a@example.com> rejected RCPT <b@example.net>: Example " + strings.Repeat("\u00e9", 200),
			"Example " + strings.Repeat("\u00e9", 112)},
		{"2026-10-20 12:00:00 H=mx.example.net [203.0.113.5]:1 rejected EHLO or HELO x: Example reason",
			"EHLO or HELO x: Example reason"},
	}
	for _, c := range cases {
		r, ok := ParseReject(c.line, rejectLoc, rejectFallback)
		if !ok || r.Detail != c.want {
			t.Errorf("%q: ok=%v detail=%q, want %q", c.line, ok, r.Detail, c.want)
		}
	}
}

var rejectSpoofCases = []struct {
	line          string
	spoofed, want Class
}{
	// A leading word makes the forged verb match inside the HELO.
	{`2026-10-20 12:00:00 H=(x rejected RCPT <c@example.net>: Mailbox is full) [203.0.113.5]:1 F=<a@example.com> rejected RCPT <b@example.net>: Sender verify failed`,
		ClassMailboxFull, ClassSenderVerify},
	// Field-shaped HELO text is not the envelope sender.
	{`2026-10-20 12:00:00 H=(x F=<c@example.net>) [203.0.113.5]:1 F=<a@example.com> rejected RCPT <b@example.net>: Sender verify failed`,
		ClassMailboxFull, ClassSenderVerify},
	// quoted local part in the recipient carrying the spam text
	{`2026-10-20 12:00:00 H=(x) [203.0.113.5]:1 F=<a@example.com> rejected RCPT <"x>: Message rejected as spam"@example.net>: No Such User Here`,
		ClassSpam, ClassOther},
	// HELO carrying a reject verb and the spam text
	{`2026-10-20 12:00:00 H=(rejected after DATA: Message rejected as spam) [203.0.113.5]:1 F=<a@example.com> rejected RCPT <b@example.net>: Sender verify failed`,
		ClassSpam, ClassSenderVerify},
	// sender carrying a second verb
	{`2026-10-20 12:00:00 H=(x) [203.0.113.5]:1 F=<"a rejected RCPT <c@example.net>: Mailbox is full"@example.com> rejected RCPT <b@example.net>: No Such User Here`,
		ClassMailboxFull, ClassOther},
	// MAIL address carrying a second verb
	{`2026-10-20 12:00:00 H=(x) [203.0.113.5]:1 rejected MAIL <"a rejected RCPT <b@example.net>: Mailbox is full"@example.com>: Access denied - Invalid HELO name (See RFC2821 192.0.2.25)`,
		ClassMailboxFull, ClassOther},
	// login carrying a verb and the spam text
	{`2026-10-20 12:00:00 H=(x) [203.0.113.5]:1 F=<a@example.com> A=dovecot_login:a rejected after DATA: Message rejected as spam rejected RCPT <b@example.net>: Sender verify failed`,
		ClassSpam, ClassOther},
	// client certificate name breaking its quotes to place a verb first
	{`2026-10-20 12:00:00 H=mx.example.net [203.0.113.5]:1 X=TLS1.3:TLS_AES_256_GCM_SHA384:256 DN="CN=a" rejected RCPT <b@example.net>: Mailbox is full "x" F=<a@example.com> rejected RCPT <c@example.net>: No Such User Here`,
		ClassMailboxFull, ClassOther},
	// remote ident before a warning that is not a reject
	{`2026-10-20 12:00:00 H=mx.example.net [203.0.113.5]:1 U=x rejected RCPT <b@example.net>: Mailbox is full Warning: example`,
		ClassMailboxFull, ClassOther},
	// HELO repeated in an RBL reason carrying mid-message texts
	{`2026-10-20 12:00:00 H=(ratelimited.example.net) [203.0.113.5]:1 F=<a@example.com> temporarily rejected RCPT <b@example.net>: JunkMail rejected - (ratelimited.example.net) [203.0.113.5]:1 is in an RBL: deferred`,
		ClassRateLimited, ClassBlocklisted},
	{`2026-10-20 12:00:00 H=(contains a virus or other harmful content) [203.0.113.5]:1 F=<a@example.com> rejected RCPT <b@example.net>: JunkMail rejected - (contains a virus or other harmful content) [203.0.113.5]:1 is in an RBL`,
		ClassMalware, ClassBlocklisted},
}

func TestParseRejectOptionalPeerFields(t *testing.T) {
	for _, c := range []struct {
		fields string
		class  Class
	}{
		{` TFO`, ClassSenderVerify},
		{` TFO*`, ClassSenderVerify},
		{` X=TLS1.3 DN="CN=x F=<c@example.net>"`, ClassSenderVerify},
		{` X=TLS1.3 DN="CN=x rejected RCPT <c@example.net>: Mailbox is full"`, ClassOther},
	} {
		line := `2026-10-20 12:00:00 H=(x) [203.0.113.5]:1` + c.fields + ` F=<a@example.com> rejected RCPT <b@example.net>: Sender verify failed`
		r, ok := ParseReject(line, rejectLoc, rejectFallback)
		if !ok || r.Class != c.class || r.IP != "203.0.113.5" || r.Sender != "a@example.com" || r.Recipient != "b@example.net" {
			t.Errorf("fields %q: got %+v, %v", c.fields, r, ok)
		}
	}
}

func TestParseRejectQuotedLogin(t *testing.T) {
	line := `2026-10-20 12:00:00 H=(x) [203.0.113.5]:1 F=<a@example.com> A=dovecot_login:"first last"@example.com rejected RCPT <b@example.net>: Sender verify failed`
	r, ok := ParseReject(line, rejectLoc, rejectFallback)
	if !ok || r.Class != ClassSenderVerify || r.IP != "203.0.113.5" || r.Sender != "a@example.com" || r.Recipient != "b@example.net" {
		t.Fatalf("quoted login: got %+v, %v", r, ok)
	}
}

func TestParseRejectSpoofs(t *testing.T) {
	for _, c := range rejectSpoofCases {
		r, ok := ParseReject(c.line, rejectLoc, rejectFallback)
		if !ok || r.Class == c.spoofed || r.Class != c.want {
			t.Errorf("%s\n ok=%v class=%q, want %q", c.line, ok, r.Class, c.want)
		}
		if r.IP != "203.0.113.5" {
			t.Errorf("%s\n ip=%q", c.line, r.IP)
		}
	}
}

func TestParseRejectIgnoresNonRejects(t *testing.T) {
	for _, line := range []string{
		"2026-10-20 12:00:00 1tAbCd-000001-Ab => b@example.net R=dkim_lookuphost T=dkim_remote_smtp H=mx.example.net [203.0.113.5] X=TLS1.3:TLS_AES_256_GCM_SHA384:256 CV=yes C=\"250 OK\"",
		`2026-10-20 12:00:00 1tAbCd-000001-Ab <= a@example.com H=mx.example.net [203.0.113.5]:1 P=esmtps S=1000 T="rejected RCPT <b@example.net>: Mailbox is full" for b@example.net`,
		`2026-10-20 12:00:00 1tAbCd-000001-Ab <= a@example.com H=mx.example.net [203.0.113.5]:1 P=esmtps S=1000 T="Re: rejected RCPT <b@example.net>: Mailbox is full" for b@example.net`,
		`2026-10-20 12:00:00 1tAbCd-000001-Ab CSM-ANTISPAM event=scan mode=enforce policy=on result=ok score=10 action="reject" decision=reject ip=203.0.113.5`,
		"2026-10-20 12:00:00 1tAbCd-000001-Ab ** b@example.net R=dkim_lookuphost T=dkim_remote_smtp H=mx.example.net [203.0.113.5] X=TLS1.3:TLS_AES_256_GCM_SHA384:256 CV=no : SMTP error from remote mail server after RCPT TO:<b@example.net>: 550 JunkMail rejected - mx.example.net [203.0.113.6]:2525 is in an RBL",
		"2026-10-20 12:00:00 1tAbCd-000001-Ab ** b@example.net (c@example.net) <c@example.net> R=dkim_lookuphost T=dkim_remote_smtp H=mx.example.net [203.0.113.5] X=TLS1.3:TLS_AES_256_GCM_SHA384:256 CV=yes : SMTP error from remote mail server after end of data: 554 5.7.1 Message rejected under suspicion of SPAM; https://www.example.net/x",
		"2026-10-20 12:00:00 1tAbCd-000001-Ab H=mx.example.net [203.0.113.5]: SMTP error from remote mail server after RCPT TO:<b@example.net>: 550 rejected RCPT <b@example.net>: No Such User Here",
		"2026-10-20 12:00:00 H=mx.example.net [203.0.113.5]:1 F=<a@example.com> Warning: rejected RCPT <b@example.net>: Mailbox is full",
		"2026-10-20 12:00:00 H=mx.example.net [203.0.113.5]:1 X=TLS1.3:TLS_AES_256_GCM_SHA384:256 Warning: rejected RCPT <b@example.net>: Mailbox is full",
		"H=mx.example.net [203.0.113.5]:1 F=<a@example.com> rejected RCPT <b@example.net>: Mailbox is full",
		"2026-10-20 12:00:00 H=mx.example.net [203.0.113.5]:1 F=<a@example.com> A=dovecot_login:a@example.com X=TLS1.3:TLS_AES_256_GCM_SHA384:256 rejected RCPT <b@example.net>: Mailbox is full",
		"2026-10-20 12:00:00 H=mx.example.net [203.0.113.5]:1 F=<a@example.com> A=dovecot_login:a@example.com A=dovecot_plain:a@example.com rejected RCPT <b@example.net>: Mailbox is full",
		"2026-10-20 12:00:00 H=mx.example.net [203.0.113.5]:1 F=<a@example.com> A= rejected RCPT <b@example.net>: Mailbox is full",
		"2026-10-20 12:00:00 H=mx.example.net [203.0.113.5]:1 F=< rejected EHLO or HELO x: Example reason",
	} {
		if r, ok := ParseReject(line, rejectLoc, rejectFallback); ok {
			t.Errorf("parsed a non-reject as %q: %s", r.Class, line)
		}
	}
}
