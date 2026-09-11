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

func FuzzRedactSensitive(f *testing.F) {
	for _, seed := range []string{
		"[cpaneld] NEW ",
		"[cpaneld] NEW :",
		"[cpaneld] NEW NEW shop:session-fixture",
		"[cpaneld] NEW shop:[REDACTED] PURGE shop:session-fixture",
		"[cpsrvd] NEW shop:session-fixture password=[REDACTED]",
		"[whostmgrd] NEW root:session-fixture",
		"[cpdavd] NEW _dav_:session-fixture",
		"password=fixture&password=other-fixture",
		`log="request token_value=first-fixture token_value=second-fixture evidence"`,
		`log="request password='quoted fixture' evidence"`,
		"log=\"password=[REDACTED]\tuser=shop\"",
		`curl https://user:fixture@example.com/?api_token=fixture&x=1`,
		"",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input string) {
		got := redactSensitive(input)
		if again := redactSensitive(got); again != got {
			t.Fatalf("redaction is not idempotent: first %q, second %q", got, again)
		}
	})
}
