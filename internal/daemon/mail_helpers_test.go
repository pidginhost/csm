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
