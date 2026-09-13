package eximlog

import "testing"

func TestMailauthDataPreservesVerifiedIdentity(t *testing.T) {
	// The optional MAIL AUTH value is xtext supplied by the client. It is
	// logged after the authenticated identity when smtp_mailauth is enabled.
	for _, envelope := range []string{
		`notice@[192.0.2.1]`,
		`notice@example.net U=remote`,
		`notice@example.net P=local`,
		`notice@example.net A=dovecot_login:other@example.net`,
		`unbalanced(`,
		`unbalanced[`,
		`unbalanced"`,
	} {
		for _, ident := range []string{"", " U=remote"} {
			line := `2026-01-01 10:00:00 1abc23-000456-AB <= sender@example.com H=mail.example [203.0.113.5]:2525` + ident + ` P=esmtpsa A=dovecot_login:alice@example.com:` + envelope + ` S=100`
			want := "alice@example.com"
			if ident != "" {
				want = ""
			}
			if got := AuthenticatedUser(line); got != want {
				t.Errorf("envelope %q, ident %q: authenticated user = %q, want %q", envelope, ident, got, want)
			}
			if got := Submitter(line); got != want {
				t.Errorf("envelope %q, ident %q: submitter = %q, want %q", envelope, ident, got, want)
			}
			if got := ClientIP(line); got != "203.0.113.5" {
				t.Errorf("envelope %q, ident %q: client IP = %q, want 203.0.113.5", envelope, ident, got)
			}
		}
	}
}
