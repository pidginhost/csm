package daemon

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// Failures and successes spell one mailbox the same way, whatever case or
// padding the client or the log used.
func TestNormalizeSprayMailbox(t *testing.T) {
	for in, want := range map[string]string{
		" User@Example.COM ": "user@example.com",
		"CPUSER":             "cpuser",
		"":                   "",
		" \t ":               "",
	} {
		if got := normalizeSprayMailbox(in); got != want {
			t.Errorf("normalizeSprayMailbox(%q) = %q, want %q", in, got, want)
		}
	}
	if got := normalizeSprayMailbox(strings.Repeat("a", 300)); len(got) != maxSprayMailboxBytes {
		t.Errorf("300-byte name kept %d bytes, want %d", len(got), maxSprayMailboxBytes)
	}
	// 254 falls inside the 85th three-byte rune, so the cut backs off to 252.
	long := strings.Repeat("\u20ac", 100)
	got := normalizeSprayMailbox(long)
	if !utf8.ValidString(got) || len(got) != 252 || !strings.HasPrefix(long, got) {
		t.Errorf("multi-byte name cut to %d bytes, valid UTF-8 = %v", len(got), utf8.ValidString(got))
	}
}
