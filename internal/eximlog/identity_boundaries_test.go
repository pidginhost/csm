package eximlog

import "testing"

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
