package alert

import (
	"strings"
	"testing"
)

// Command lines come from attacker-controlled process arguments and log text.
// Redaction must stay total and idempotent for malformed quoting, NUL-delimited
// argv data, and arbitrary bytes.
func FuzzRedactCommandLine(f *testing.F) {
	for _, seed := range []string{
		"mysql\x00-psecret\x00db\x00",
		`pg_dump --password="unterminated`,
		`sshpass -p's e c r e t' ssh host`,
		`curl https://user:pass@example.test/hook?token=secret`,
		"\x00\x00\x00",
		"",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input string) {
		got := RedactCommandLine(input)
		if strings.IndexByte(got, 0) >= 0 {
			t.Fatal("redacted command line retained a NUL byte")
		}
		if again := RedactCommandLine(got); again != got {
			t.Fatalf("redaction is not idempotent: first %q, second %q", got, again)
		}
	})
}
