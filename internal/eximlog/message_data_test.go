package eximlog

import (
	"strings"
	"testing"
)

// peerLikeText imitates a logged peer followed by remote ident metadata.
var peerLikeText = []string{
	`[192.0.2.1] U=x`,
	`[192.0.2.1]:25 U=x`,
	`[2001:db8::1]:25 I=[192.0.2.25]:25 TFO* U=x`,
}

// Senders and connecting clients write subjects, message IDs, addresses and
// login names in every Exim configuration. That text follows the logged
// peer and must not remove the peer or the authenticated identity, or it
// would hide the sender from rate limits and the client from blocking.
func TestMessageDataCannotHideArrivalIdentity(t *testing.T) {
	const arrival = "2026-01-01 10:00:00 1abc23-000456-AB <= sender@example.com H=mail.example (helo.example) [203.0.113.5]:2525 P=esmtpsa X=TLS1.3:TLS_AES_256_GCM_SHA384:256 CV=no A=dovecot_login:alice@example.com S=100 "
	for _, text := range peerLikeText {
		quoted := strings.ReplaceAll(text, `"`, `\"`)
		for name, tail := range map[string]string{
			"subject":    `id=x@example.com T="Invoice ` + quoted + `"`,
			"message id": `id="` + quoted + `"@example.com T="hello"`,
			"sender":     `id=x@example.com T="hello" from <"` + quoted + `"@example.org>`,
			"recipient":  `id=x@example.com T="hello" for "` + quoted + `"@example.net`,
		} {
			line := arrival + tail
			if got := AuthenticatedUser(line); got != "alice@example.com" {
				t.Errorf("%s %q: AuthenticatedUser = %q, want alice@example.com", name, text, got)
			}
			if got := Submitter(line); got != "alice@example.com" {
				t.Errorf("%s %q: Submitter = %q, want alice@example.com", name, text, got)
			}
			if got := ClientIP(line); got != "203.0.113.5" {
				t.Errorf("%s %q: ClientIP = %q, want 203.0.113.5", name, text, got)
			}
		}
	}
}

func TestFailureDetailsCannotHidePeer(t *testing.T) {
	for _, text := range peerLikeText {
		for _, line := range []string{
			`2026-01-01 10:00:00 dovecot_login authenticator failed for (helo.example) [203.0.113.5]:2525: 535 Incorrect authentication data (set_id=` + text + `)`,
			`2026-01-01 10:00:00 dovecot_login authenticator failed for H=mail.example (helo.example) [203.0.113.5]:2525 I=[192.0.2.25]:587: 535 Incorrect authentication data (set_id=` + text + `)`,
			`2026-01-01 10:00:00 H=(helo.example) [203.0.113.5]:2525 F=<"` + text + `"@example.com> rejected RCPT <user@example.net>: relay not permitted`,
			`2026-01-01 10:00:00 H=(helo.example) [203.0.113.5]:2525 F=<user@example.com> rejected RCPT <"` + text + `"@example.net>: relay not permitted`,
		} {
			if got := ClientIP(line); got != "203.0.113.5" {
				t.Errorf("ClientIP(%q) = %q, want 203.0.113.5", line, got)
			}
		}
	}
}

// Exim escapes quotes and backslashes in the logged subject. Any subject a
// sender chooses must leave the peer and authenticated identity intact.
func FuzzSubjectCannotHideArrivalIdentity(f *testing.F) {
	for _, text := range peerLikeText {
		f.Add(text)
	}
	f.Add(`") [203.0.113.9]:2525 U=" P=esmtp S=200`)
	f.Fuzz(func(t *testing.T, subject string) {
		// Exim writes non-printing characters as escape sequences.
		for _, r := range subject {
			if r < 0x20 || r > 0x7e {
				return
			}
		}
		escaped := strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(subject)
		line := "2026-01-01 10:00:00 1abc23-000456-AB <= sender@example.com H=mail.example [203.0.113.5]:2525 P=esmtpsa A=dovecot_login:alice@example.com S=100 id=x@example.com T=\"" + escaped + "\" for user@example.net"
		if got := AuthenticatedUser(line); got != "alice@example.com" {
			t.Fatalf("subject %q changed authenticated user to %q", subject, got)
		}
		if got := ClientIP(line); got != "203.0.113.5" {
			t.Fatalf("subject %q changed client address to %q", subject, got)
		}
	})
}
