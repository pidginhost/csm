package signatures

import (
	"bytes"
	"regexp"
	"testing"
)

// Custom YAML rules may use syntax absent from the shipped rules, so mutate
// both the regex and its input instead of holding the rule set fixed.
func FuzzRegexGatesAreSound(f *testing.F) {
	for _, seed := range regexGateSoundnessCases {
		f.Add(seed.src, []byte(seed.content))
	}
	f.Fuzz(func(t *testing.T, src string, content []byte) {
		re, err := regexp.Compile(src)
		if err != nil {
			return
		}
		cr := &compiledRegex{Regexp: re, gate: gateFor(src)}
		if got, want := newRegexEval(content).match(cr), re.Match(content); got != want {
			t.Fatalf("gate %q changed match for regex %q on %q: got %t, want %t", cr.gate, src, content, got, want)
		}
	})
}

func FuzzReferencedPayloadPaths(f *testing.F) {
	f.Add([]byte("<?php include'payload.jpe';"))
	f.Add([]byte("<?php $p = '/assets/logo.png'; include($p);"))
	f.Add([]byte("<?php include 'same.png'; include 'same.png';"))
	f.Add([]byte("<?php include 'code.php';"))
	f.Fuzz(func(t *testing.T, content []byte) {
		paths := ReferencedPayloadPaths(content)
		if len(paths) > maxReferencedPayloadPaths {
			t.Fatalf("unbounded path count: %d", len(paths))
		}
		seen := make(map[string]bool)
		for _, path := range paths {
			if seen[path] || path == "" || !bytes.Contains(content, []byte(path)) {
				t.Fatalf("duplicate or fabricated path: %q", path)
			}
			seen[path] = true
		}
	})
}

func FuzzSpamBase64Links(f *testing.F) {
	for _, seed := range []string{
		`<a href="http://example.com/">pills</a>`,
		"x<a\nHREF='https://example.com/'>pills</a>",
		`xx<a href=//example.com/>pills</a>`,
		`<a href="http-help.html">help</a>`,
		`<svg><use href="#logo"/></svg>`,
		"<a href=\"http\u017f://example.com/\">local name</a>",
	} {
		f.Add([]byte(seed))
	}
	// Compare the encoded rule with an independent decoded-text oracle;
	// mutating binary neighbours also exercises the partial sextet edges.
	decodedLink := regexp.MustCompile(`[\t\n\f\r ][hH][rR][eE][fF]=["']?(?:[hH][tT][tT][pP][sS]?:)?//`)
	f.Fuzz(func(t *testing.T, decoded []byte) {
		scanner := spamBase64Scanner(t)
		got := hasRule(scanner.ScanContent(echoBase64(string(decoded)), ".php"), "spam_base64_links")
		if want := decodedLink.Match(decoded); got != want {
			t.Fatalf("encoded rule = %t, decoded oracle = %t for %q", got, want, decoded)
		}
	})
}
