package mailstats

import (
	"net"
	"slices"
	"strings"
	"testing"
	"time"
	"unicode"
)

func FuzzParseReject(f *testing.F) {
	for _, c := range rejectClassCases {
		f.Add(c.line)
	}
	for _, c := range rejectSpoofCases {
		f.Add(c.line)
	}
	f.Fuzz(func(t *testing.T, line string) {
		r, ok := ParseReject(line, rejectLoc, rejectFallback)
		if n := len([]rune(r.Detail)); n > 120 {
			t.Fatalf("detail has %d runes", n)
		}
		if strings.ContainsFunc(r.Detail, unicode.IsControl) {
			t.Fatalf("detail contains a control character: %q", r.Detail)
		}
		if !ok {
			return
		}
		if !slices.Contains(Classes, r.Class) {
			t.Fatalf("class %q not in Classes", r.Class)
		}
		if r.IP != "" && net.ParseIP(r.IP) == nil {
			t.Fatalf("ip %q is not an address", r.IP)
		}
	})
}

func FuzzParsePostfixReject(f *testing.F) {
	for _, c := range postfixRejectCases {
		f.Add(c.line)
	}
	f.Fuzz(func(t *testing.T, line string) {
		r, ok := ParsePostfixReject(line, rejectLoc, rejectFallback)
		if n := len([]rune(r.Detail)); n > 120 {
			t.Fatalf("detail has %d runes", n)
		}
		if strings.ContainsFunc(r.Detail, unicode.IsControl) {
			t.Fatalf("detail contains a control character: %q", r.Detail)
		}
		if !ok {
			return
		}
		if !slices.Contains(Classes, r.Class) {
			t.Fatalf("class %q not in Classes", r.Class)
		}
		if net.ParseIP(r.IP) == nil {
			t.Fatalf("ip %q is not an address", r.IP)
		}
		// Whatever the rejected name holds, a reply that carries two
		// different reject kinds is never classed by either. The reply
		// ends at the last envelope marker.
		reply := line
		if i := strings.LastIndex(line, "; from=<"); i >= 0 {
			reply = line[:i]
		}
		if strings.Contains(reply, ">: Sender address rejected: ") && strings.Contains(reply, ">: Recipient address rejected: ") &&
			(r.Class == ClassSenderVerify || r.Class == ClassUnknownRecipient) {
			t.Fatalf("mixed kinds classed as %q: %q", r.Class, line)
		}
	})
}

func FuzzRejectUntrustedFields(f *testing.F) {
	for _, payload := range []string{
		"x",
		"x rejected RCPT <b@example.net>: Mailbox is full",
		`x F=<b@example.net>`,
		`x" rejected after DATA: Message rejected as spam`,
		"contains a virus or other harmful content",
	} {
		f.Add(payload)
	}
	f.Fuzz(func(t *testing.T, payload string) {
		const prefix = "2026-10-20 12:00:00 H="
		const peer = " [203.0.113.5]:1"
		const sender = " F=<a@example.com>"
		const reject = " rejected RCPT <b@example.net>: Sender verify failed"
		quoted := `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(payload) + `"@example.com`
		for _, line := range []string{
			prefix + "(" + payload + ")" + peer + sender + reject,
			prefix + "(x)" + peer + " F=<" + quoted + ">" + reject,
			prefix + "(x)" + peer + sender + " A=dovecot_login:" + payload + reject,
			prefix + "(x)" + peer + sender + " rejected RCPT <" + quoted + ">: Sender verify failed",
		} {
			r, ok := ParseReject(line, rejectLoc, rejectFallback)
			if ok && r.Class != ClassSenderVerify && r.Class != ClassOther {
				t.Fatalf("client text changed the class to %q: %q", r.Class, line)
			}
		}
	})
}

func FuzzLineTime(f *testing.F) {
	for _, line := range []string{
		"2026-10-20 12:00:00.123 +0300 message",
		"2026-10-20T12:00:00.123Z message",
		"Oct 20 12:00:00 host message",
		"Feb 29 12:00:00 host message",
		"",
	} {
		f.Add(line)
	}
	f.Fuzz(func(t *testing.T, line string) {
		got := LineTime(line, rejectLoc, rejectFallback)
		if got.After(rejectFallback.Add(time.Hour)) {
			t.Fatalf("future timestamp: %v", got)
		}
	})
}
