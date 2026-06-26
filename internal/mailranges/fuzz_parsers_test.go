package mailranges

import (
	"strings"
	"testing"
)

// FuzzParseSPFRecord exercises the pure record-token parser against arbitrary
// input. parseSPFRecord makes no network calls and must never panic regardless
// of the TXT string content. Unbounded recursion cannot occur here because the
// function parses ONE record's tokens; recursion over DNS lives in ResolveSPF.
//
// Run the seed corpus as regression tests with `go test -run=Fuzz ./internal/mailranges/`.
// Run actual fuzzing with `go test -fuzz=FuzzParseSPFRecord -fuzztime=30s ./internal/mailranges/`.
func FuzzParseSPFRecord(f *testing.F) {
	// Seed: include directive
	f.Add("v=spf1 include:_spf.example.com -all")
	// Seed: redirect directive
	f.Add("v=spf1 redirect=_spf.example.com")
	// Seed: ip4 mechanism
	f.Add("v=spf1 ip4:8.8.8.0/24 -all")
	// Seed: ip6 mechanism
	f.Add("v=spf1 ip6:2001:4860:4860::/48 -all")
	// Seed: mixed mechanisms
	f.Add("v=spf1 ip4:8.8.8.0/24 ip6:2001:4860:4860::/48 include:a.example.com redirect=b.example.com")
	// Seed: malformed - not a v=spf1 record
	f.Add("not a spf record at all")
	// Seed: malformed prefix
	f.Add("v=spf1 ip4:notacidr -all")
	// Seed: empty string
	f.Add("")
	// Seed: huge token (4096 bytes of 'a')
	f.Add("v=spf1 include:" + strings.Repeat("a", 4096))
	// Seed: random-looking bytes mixed into a record
	f.Add("v=spf1 ip4:\x00\xff\x7f\x80/8 ip6:\x01\x02 -all")
	// Seed: multiple redirect= directives (should error, not panic)
	f.Add("v=spf1 redirect=a.example.com redirect=b.example.com -all")
	// Seed: multiple redirect= where the first value is empty (must still error)
	f.Add("v=spf1 redirect= redirect=b.example.com -all")
	// Seed: empty include/redirect values
	f.Add("v=spf1 include: redirect= -all")

	f.Fuzz(func(t *testing.T, txt string) {
		// Must never panic. Any error return is acceptable.
		_, _ = parseSPFRecord(txt)
	})
}
