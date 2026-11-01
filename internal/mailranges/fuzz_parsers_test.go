package mailranges

import (
	"slices"
	"strings"
	"testing"
)

// FuzzParseSPFRecord exercises the pure record-token parser against arbitrary
// input. parseSPFRecord makes no network calls and must never panic regardless
// of the TXT string content. Unbounded recursion cannot occur here because the
// function parses ONE record's tokens; recursion over DNS lives in
// resolveSPFRec, shared by ResolveSPF and ResolveSPFPolicy.
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
	// Seed: valid bare IP mechanisms and explicit pass qualifiers
	f.Add("v=spf1 +ip4:8.8.8.8 +ip6:2001:4860:4860::8888 +include:a.example.com -all")
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
	// Seeds: ptr forms the strict resolver collects or rejects
	f.Add("v=spf1 ptr -all")
	f.Add("v=spf1 ptr: -all")
	f.Add("v=spf1 ptr:%{d} -all")
	// Seed: macro-named include and redirect targets
	f.Add("v=spf1 include:%{i}._spf.example.com redirect=%{d}.example.com")

	f.Fuzz(func(t *testing.T, txt string) {
		// Must never panic, and any error return is acceptable. The firewall
		// path must never see ptr domains; strict mode keeps only normalised
		// ones and never follows a macro-named target.
		legacy, _ := parseSPFRecord(txt, "example.com", false)
		if len(legacy.ptrs) != 0 {
			t.Fatalf("legacy parse of %q collected ptr domains %q", txt, legacy.ptrs)
		}
		strict, err := parseSPFRecord(txt, "example.com", true)
		if err != nil {
			return
		}
		if slices.ContainsFunc(append(strict.includes, strict.redirect), func(s string) bool { return strings.Contains(s, "%") }) {
			t.Fatalf("strict parse of %q kept a macro target: %q %q", txt, strict.includes, strict.redirect)
		}
		for _, p := range strict.ptrs {
			if norm, err := spfPTRDomain(p); err != nil || norm != p {
				t.Fatalf("strict parse of %q kept ptr domain %q that is not normalised (%q, %v)", txt, p, norm, err)
			}
		}
	})
}
