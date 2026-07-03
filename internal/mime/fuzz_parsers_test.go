package mime

import (
	"os"
	"path/filepath"
	"testing"
)

// The Exim -H parser turns a spool header file into the envelope + RFC 5322
// header set that drives attachment extraction. The header bytes are populated
// from attacker-controlled message headers, so a crafted -H that panics the
// parser is a local DoS against the email-AV path. This target exercises the
// length+flag prefix stripping, folded continuations, and deleted-header
// handling against arbitrary input.
//
// Run locally with:
//
//	go test -run=xxx -fuzz=FuzzParseEximHeaderData -fuzztime=60s ./internal/mime/
func FuzzParseEximHeaderData(f *testing.F) {
	// Real-format golden fixtures as the primary seeds.
	for _, name := range []string{"simple-H", "multipart-H", "singlepart-H"} {
		if data, err := os.ReadFile(filepath.Join("testdata", name)); err == nil {
			f.Add(data)
		}
	}

	// Crafted edge cases.
	f.Add([]byte("id-H\nuser 1 1\n<u@example.com>\n0 0\n-local\n1\nr@example.com\n\n048F From: a@b\n028T To: c@d\n"))
	// 4-digit (variable-width) length prefix.
	f.Add([]byte("id-H\nuser 1 1\n<u@example.com>\n0 0\n\n1010  Subject: oversized header value\n"))
	// Deleted header ('*') plus a folded continuation.
	f.Add([]byte("id-H\nuser 1 1\n<u@example.com>\n0 0\n\n020* X-Old: gone\n039  Content-Type: multipart/mixed;\n\tboundary=\"b\"\n"))
	// Missing separator / truncated / garbage.
	f.Add([]byte("id-H\nuser 1 1\n"))
	f.Add([]byte("not an exim spool file at all"))
	f.Add([]byte(""))
	f.Add([]byte("\n\n\n\n"))

	f.Fuzz(func(t *testing.T, data []byte) {
		// Must not panic; parseEximHeaderData is fail-open by contract.
		env, hdrs := parseEximHeaderData(data)
		if env == nil || hdrs == nil {
			t.Fatal("parseEximHeaderData must return non-nil envelope and headers")
		}
	})
}
