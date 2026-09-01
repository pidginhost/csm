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
