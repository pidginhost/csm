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
		" User@Example.COM ":    "user@example.com",
		" User@Example.COM. ":   "user@example.com",
		"user@example.com..":    "user@example.com..",
		"user@example..com.":    "user@example..com.",
		"user@.":                "user@.",
		"user.":                 "user.",
		"CPUSER":                "cpuser",
		"\u0130nfo@Example.COM": "\u0130nfo@example.com",
		"\u212aate@example.com": "\u212aate@example.com",
		"":                      "",
		" \t ":                  "",
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

// Normalising twice changes nothing, so a tracker may normalise at its
// boundary and mailSpray can trust the key it gets.
func TestNormalizeSprayMailboxIdempotent(t *testing.T) {
	// The cut lands right after the space, which must not survive as padding.
	spaced := strings.Repeat("a", 253) + " " + strings.Repeat("b", 10)
	if got := normalizeSprayMailbox(spaced); got != strings.Repeat("a", 253) {
		t.Errorf("cut before padding kept %q at the end", got[len(got)-2:])
	}
	if got := normalizeSprayMailbox(strings.Repeat("a", 254)); len(got) != 254 {
		t.Errorf("254-byte name kept %d bytes, want 254", len(got))
	}
	if got := normalizeSprayMailbox(strings.Repeat("a", 255)); len(got) != 254 {
		t.Errorf("255-byte name kept %d bytes, want 254", len(got))
	}
	for _, in := range []string{spaced, strings.Repeat("A", 300), " Mixed@Example.COM ", "user@example.com.", "user@example.com..", strings.Repeat("\xff", 300)} {
		once := normalizeSprayMailbox(in)
		if twice := normalizeSprayMailbox(once); twice != once {
			t.Errorf("normalize(normalize(%.20q...)) = %.20q, want %.20q", in, twice, once)
		}
	}
}

func TestNormalizeSprayMailboxIdempotentAtTruncation(t *testing.T) {
	for _, space := range []string{" ", "\t", "\u2003"} {
		want := strings.Repeat("a", maxSprayMailboxBytes-len(space))
		input := want + space + "B"
		got := normalizeSprayMailbox(input)
		if got != want {
			t.Errorf("truncated key = %q, want %q", got, want)
		}
		if again := normalizeSprayMailbox(got); again != got {
			t.Errorf("normalizing twice changed %q to %q", got, again)
		}
	}
}
