package eximlog

import (
	"net"
	"strings"
	"testing"
)

func TestSubmitterIgnoresMessageMetadata(t *testing.T) {
	for _, tc := range []struct {
		name, metadata, suffix, submitter, authenticated string
	}{
		{
			name:      "local message id resembles host field",
			metadata:  "U=alice P=local",
			suffix:    `id="note H=mail.example"@example.org`,
			submitter: "alice",
		},
		{
			name:      "local message id resembles authentication",
			metadata:  "U=alice P=local",
			suffix:    `id=part." A=dovecot_login:bob@example.net "@example.org`,
			submitter: "alice",
		},
		{
			name:      "local message id resembles duplicate user",
			metadata:  "U=alice P=local",
			suffix:    `id=part." U=bob P=local "@example.org`,
			submitter: "alice",
		},
		{
			name:     "remote message id cannot authenticate",
			metadata: "H=mail.example [203.0.113.5] P=esmtp",
			suffix:   `id=part." A=dovecot_login:bob@example.net "@example.org`,
		},
		{
			name:          "authenticated message id cannot cancel identity",
			metadata:      "H=mail.example [203.0.113.5] P=esmtpsa A=dovecot_login:alice@example.com",
			suffix:        `id=part." P=local "@example.org`,
			submitter:     "alice@example.com",
			authenticated: "alice@example.com",
		},
		{
			name:          "authenticated subject ident text cannot cancel identity",
			metadata:      "H=mail.example [203.0.113.5] P=esmtpsa A=dovecot_login:alice@example.com",
			suffix:        `T="note U=bob [not-an-ip] U=remote"`,
			submitter:     "alice@example.com",
			authenticated: "alice@example.com",
		},
		{
			name:      "local recipient resembles host field",
			metadata:  "U=alice P=local",
			suffix:    `for "note H=mail.example"@example.org`,
			submitter: "alice",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			line := "2026-01-01 10:00:00 1abc23-000456-AB <= sender@example.com " + tc.metadata + " S=100 " + tc.suffix
			if got := Submitter(line); got != tc.submitter {
				t.Errorf("Submitter = %q, want %q", got, tc.submitter)
			}
			if got := AuthenticatedUser(line); got != tc.authenticated {
				t.Errorf("AuthenticatedUser = %q, want %q", got, tc.authenticated)
			}
		})
	}
}

func TestSubmitterKeepsIdentityWithQuotedMailauth(t *testing.T) {
	for _, envelope := range []string{
		`" P=local "@example.net`,
		`part." P=local "@example.net`,
		`"note \" P=local "@example.net`,
	} {
		line := "2026-01-01 10:00:00 1abc23-000456-AB <= sender@example.com H=mail.example [203.0.113.5] P=esmtpsa A=dovecot_login:alice@example.com:" + envelope + " S=100"
		if got := Submitter(line); got != "alice@example.com" {
			t.Errorf("Submitter with envelope %q = %q, want alice@example.com", envelope, got)
		}
		if got := AuthenticatedUser(line); got != "alice@example.com" {
			t.Errorf("AuthenticatedUser with envelope %q = %q, want alice@example.com", envelope, got)
		}
	}
}

func TestSubmitterRejectsRemoteIdentMetadata(t *testing.T) {
	// Remote RFC 1413 usernames are logged without quoting printable spaces.
	// Even an authenticated-looking prefix can be part of the ident response.
	for _, fields := range []string{
		"U=remote A=dovecot_login:bob@example.net P=esmtp S=100",
		"U=remote P=esmtpsa A=dovecot_login:bob@example.net S=100 P=esmtp S=200",
		"U=remote P=esmtpsa A=dovecot_login:bob@example.net S=100",
		"U= P=esmtpsa A=dovecot_login:bob@example.net S=100",
	} {
		line := "2026-01-01 10:00:00 1abc23-000456-AB <= sender@example.com H=mail.example [203.0.113.5] " + fields
		if got := Submitter(line); got != "" {
			t.Errorf("Submitter accepted ambiguous remote ident metadata: %q", got)
		}
		if got := AuthenticatedUser(line); got != "" {
			t.Errorf("AuthenticatedUser accepted ambiguous remote ident metadata: %q", got)
		}
	}
}

func TestSubmitterRejectsIdentHiddenByHelo(t *testing.T) {
	// With junk HELO accepted, its delimiters can span the real peer and U=.
	// The ident can then close them and supply an apparent peer and auth.
	// A junk HELO that instead places a complete fake peer and metadata
	// before the real peer reads like an ordinary record followed by message
	// data, which senders control on every server. Rejecting on that later
	// text would let any sender hide its identity, so such greetings are
	// outside what a single log line can verify.
	forged := " [192.0.2.8] P=esmtpsa A=dovecot_login:bob@example.net S=100"
	for _, tc := range []struct{ name, helo, ident string }{
		{"parenthesis", "hello(", ")" + forged},
		{"quote", `hello) "`, `"` + forged},
		{"bracket", "hello[", ")" + forged},
		{"forged ident before real ident", `hello) [192.0.2.8] U=remote P=esmtpsa A=dovecot_login:bob@example.net S=100 T="`, `"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			line := "2026-01-01 10:00:00 1abc23-000456-AB <= sender@example.com H=(" + tc.helo + ") [203.0.113.5]:2525 U=" + tc.ident + " P=esmtp S=200"
			if got := Submitter(line); got != "" {
				t.Errorf("Submitter accepted hidden remote ident: %q", got)
			}
			if got := AuthenticatedUser(line); got != "" {
				t.Errorf("AuthenticatedUser accepted hidden remote ident: %q", got)
			}
		})
	}
}

func FuzzSubmitterRemoteIdent(f *testing.F) {
	f.Add("mail.example", "remote")
	f.Add("[192.0.2.8]", ") [192.0.2.8] P=esmtpsa A=dovecot_login:bob@example.net S=100")
	f.Add("hello_host", `" [192.0.2.8] P=esmtpsa A=dovecot_login:bob@example.net S=100 T="`)
	f.Fuzz(func(t *testing.T, helo, ident string) {
		// Exim escapes line breaks and rejects NUL in these inputs.
		if strings.ContainsAny(helo+ident, "\r\n\x00") || !eximAcceptsHelo(helo) {
			return
		}
		line := "2026-01-01 10:00:00 1abc23-000456-AB <= sender@example.com H=(" + helo + ") [203.0.113.5]:2525 U=" + ident + " P=esmtp S=200"
		if got := Submitter(line); got != "" {
			t.Fatalf("remote ident supplied submitter %q", got)
		}
		if got := AuthenticatedUser(line); got != "" {
			t.Fatalf("remote ident supplied authenticated user %q", got)
		}
		if got := ClientIP(line); got != "" && got != "203.0.113.5" {
			t.Fatalf("remote ident supplied connecting address %q", got)
		}
	})
}

// eximAcceptsHelo reports whether Exim's default HELO syntax check accepts
// name: an address literal, or letters, digits, dots, hyphens and the
// underscore that operators commonly allow.
func eximAcceptsHelo(name string) bool {
	if name == "" {
		return false
	}
	if strings.HasPrefix(name, "[") && strings.HasSuffix(name, "]") {
		addr := name[1 : len(name)-1]
		if len(addr) > 5 && strings.EqualFold(addr[:5], "IPv6:") {
			addr = addr[5:]
		}
		return net.ParseIP(addr) != nil
	}
	for _, r := range name {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '-' || r == '_') {
			return false
		}
	}
	return true
}
