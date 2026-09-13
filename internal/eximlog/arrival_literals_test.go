package eximlog

import "testing"

func TestArrivalAddressLiteralsPreserveIdentity(t *testing.T) {
	for _, tail := range []string{
		`id=notice@[192.0.2.1] T="hello"`,
		`id=notice@[2001:db8::1] T="hello"`,
		`id=notice@example.com for recipient@[192.0.2.1]`,
		`id=notice@example.com for recipient@[2001:db8::1]`,
	} {
		line := `2026-01-01 10:00:00 1abc23-000456-AB <= sender@example.com H=mail.example [203.0.113.5]:2525 P=esmtpsa A=dovecot_login:alice@example.com S=100 ` + tail
		if got := ClientIP(line); got != "203.0.113.5" {
			t.Errorf("%s: ClientIP = %q, want 203.0.113.5", tail, got)
		}
		if got := AuthenticatedUser(line); got != "alice@example.com" {
			t.Errorf("%s: AuthenticatedUser = %q, want alice@example.com", tail, got)
		}
		if got := Submitter(line); got != "alice@example.com" {
			t.Errorf("%s: Submitter = %q, want alice@example.com", tail, got)
		}
	}
}

func TestArrivalAddressLiteralCannotSupplyMissingPeer(t *testing.T) {
	line := `2026-01-01 10:00:00 1abc23-000456-AB <= sender@example.com H=mail.example P=esmtp S=100 id=notice@[192.0.2.1]`
	if got := ClientIP(line); got != "" {
		t.Fatalf("message ID supplied client IP %q", got)
	}
}

func TestLocalArrivalMessageIDCannotSupplyPeer(t *testing.T) {
	for _, id := range []string{
		`"x H=mail.example [192.0.2.1] P=a \"tail"@example.com`,
		`"SMTP connection from [192.0.2.1] P=a \"tail"@example.com`,
	} {
		line := `2026-01-01 10:00:00 1abc23-000456-AB <= sender@example.com U=alice P=local S=100 id=` + id
		if got := ClientIP(line); got != "" {
			t.Errorf("message ID %s supplied client IP %q", id, got)
		}
		if start, ok := HFieldStart(line); ok {
			t.Errorf("message ID %s supplied host field at %d", id, start)
		}
	}
}
