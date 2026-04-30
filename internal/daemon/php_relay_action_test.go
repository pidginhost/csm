package daemon

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestMsgIDPattern_AcceptsValid(t *testing.T) {
	cases := []string{"1wHpIU-0000000G8Fo-1FA1", "abc-def-1234567890abcdef"}
	for _, c := range cases {
		if !msgIDPattern.MatchString(c) {
			t.Errorf("expected match for %q", c)
		}
	}
}

func TestMsgIDPattern_RejectsInvalid(t *testing.T) {
	cases := []string{"", "short", "id with space", "id;rm-rf", "id\nnewline", strings.Repeat("a", 64)}
	for _, c := range cases {
		if msgIDPattern.MatchString(c) {
			t.Errorf("expected NO match for %q", c)
		}
	}
}

func TestActionRateLimiter_AllowsThenDenies(t *testing.T) {
	rl := newActionRateLimiter(3)
	if !rl.consumeN(2) {
		t.Fatal("first 2 should consume")
	}
	if !rl.consumeN(1) {
		t.Fatal("up to budget should still consume")
	}
	if rl.consumeN(1) {
		t.Fatal("over budget must deny")
	}
}

func TestActionRateLimiter_RefillsAfterMinute(t *testing.T) {
	rl := newActionRateLimiter(2)
	rl.now = func() time.Time { return time.Unix(0, 0) }
	rl.consumeN(2)
	if rl.consumeN(1) {
		t.Fatal("must be denied at boundary")
	}
	rl.now = func() time.Time { return time.Unix(61, 0) }
	if !rl.consumeN(1) {
		t.Fatal("after 61s the bucket should refill")
	}
}

func TestFreezeErrIsAlreadyGone(t *testing.T) {
	cases := []struct {
		stderr string
		want   bool
	}{
		{"exim: message not found", true},
		{"spool file not found for 1abc-DEF", true},
		{"no such message", true},
		{"could not read spool: permission denied", false},
		{"", false},
	}
	for _, c := range cases {
		if got := freezeErrIsAlreadyGone(c.stderr); got != c.want {
			t.Errorf("freezeErrIsAlreadyGone(%q) = %v, want %v", c.stderr, got, c.want)
		}
	}
}

func TestSpoolScanMatchingScript_ReturnsMatchingMsgIDs(t *testing.T) {
	spoolRoot := t.TempDir()
	sub := filepath.Join(spoolRoot, "k")
	_ = os.MkdirAll(sub, 0o755)

	// Match.
	body := func(script string) string {
		return "id-H\nu 1 1\n<u@example.com>\n0 0\n-local\n1\nrcpt@example.com\n\n037T To: rcpt@example.com\n132  X-PHP-Script: " + script + " for 192.0.2.1\n"
	}
	_ = os.WriteFile(filepath.Join(sub, "11abcdefghij1234-H"), []byte(body("attacker.example.com/x.php")), 0o644)
	_ = os.WriteFile(filepath.Join(sub, "21bbcdefghij1234-H"), []byte(body("attacker.example.com/x.php")), 0o644)
	_ = os.WriteFile(filepath.Join(sub, "31ccdefghij1234XX-H"), []byte(body("other.example.com/y.php")), 0o644)

	got := spoolScanMatchingScript(spoolRoot, scriptKey("attacker.example.com:/x.php"))
	if len(got) != 2 {
		t.Fatalf("matched = %v, want 2 entries", got)
	}
}
