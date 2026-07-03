package daemon

import "testing"

// --- extractMailHoldSender --------------------------------------------

func TestExtractMailHoldSenderStandard(t *testing.T) {
	line := "Rate-limiting hold: Sender user@example.com exceeded 500/hr"
	if got := extractMailHoldSender(line); got != "user@example.com" {
		t.Errorf("got %q", got)
	}
}

func TestExtractMailHoldSenderDomain(t *testing.T) {
	line := "Rate-limiting hold: Domain example.com exceeded rate"
	if got := extractMailHoldSender(line); got != "example.com" {
		t.Errorf("got %q", got)
	}
}

func TestExtractMailHoldSenderEndOfLine(t *testing.T) {
	line := "Rate-limiting hold: Sender bob@test.com"
	if got := extractMailHoldSender(line); got != "bob@test.com" {
		t.Errorf("got %q", got)
	}
}

func TestExtractMailHoldSenderMissing(t *testing.T) {
	if got := extractMailHoldSender("no sender or domain keyword"); got != "" {
		t.Errorf("got %q", got)
	}
}

// --- extractBracketedIP (daemon's version, not checks') ---------------

func TestDaemonExtractBracketedIPLast(t *testing.T) {
	line := "H=hostname [203.0.113.5]:12345"
	if got := extractBracketedIP(line); got != "203.0.113.5" {
		t.Errorf("got %q", got)
	}
}

func TestDaemonExtractBracketedIPNone(t *testing.T) {
	if got := extractBracketedIP("no brackets here"); got != "" {
		t.Errorf("got %q", got)
	}
}

func TestDaemonExtractBracketedIPHostname(t *testing.T) {
	// [hostname] without digits should return empty
	if got := extractBracketedIP("[hostname.example.com]"); got != "" {
		t.Errorf("hostname should return empty, got %q", got)
	}
}

// REL-05: an exim acceptance line whose Subject contains square brackets must
// not have that Subject token mistaken for the client IP. The old "last
// bracket" scan parsed T="Order [20260701-123]" as an "IP" and tripped the
// cloud-relay multi-IP detector with garbage sources.
func TestDaemonExtractBracketedIP_IgnoresSubjectBrackets(t *testing.T) {
	line := `2026-07-01 12:00:00 1abc-DEF-01 <= sender@example.com H=mail.example.com (helo.example) [203.0.113.5]:41000 P=esmtpa A=dovecot_login:user@example.com S=1200 id=x@x T="Order [20260701-123] shipped" for rcpt@example.net`
	if got := extractBracketedIP(line); got != "203.0.113.5" {
		t.Errorf("extractBracketedIP = %q, want the H= client IP 203.0.113.5 (not the Subject bracket)", got)
	}
}

// REL-05: a HELO string carrying its own bracketed token must be skipped in
// favour of the real [IP]:port that follows in the same H= field.
func TestDaemonExtractBracketedIP_SkipsBracketedHelo(t *testing.T) {
	line := `2026-07-01 12:00:00 1abc-DEF-01 <= s@example.com H=nic.example (EHLO [not-an-ip]) [198.51.100.9]:2525 for r@example.net`
	if got := extractBracketedIP(line); got != "198.51.100.9" {
		t.Errorf("extractBracketedIP = %q, want 198.51.100.9", got)
	}
}
