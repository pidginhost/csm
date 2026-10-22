package signatures

import (
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
)

// spam_base64_links targets hidden links echoed from a base64 literal. Plugins
// and themes echo base64 literals that are images too: a newsletter plugin's
// 1x1 open-tracking GIF, an inline SVG logo. Only a literal that decodes to a
// link with an external URL prefix is the spam shape.

func echoBase64(decoded string) []byte {
	return []byte("<?php\necho base64_decode('" + base64.StdEncoding.EncodeToString([]byte(decoded)) + "');\n")
}

func spamBase64Scanner(t *testing.T) *Scanner {
	t.Helper()
	scanner := loadRepoScanner(t)
	if err := scanner.LoadError(); err != nil {
		t.Fatal(err)
	}
	for _, rule := range scanner.rules {
		if rule.Name == "spam_base64_links" {
			return &Scanner{rules: []Rule{rule}}
		}
	}
	t.Fatal("spam_base64_links is missing")
	return nil
}

func TestSpamBase64Links_HTMLVariants(t *testing.T) {
	scanner := spamBase64Scanner(t)
	// Attribute names are ASCII case-insensitive; folding base64 text does
	// not provide that property for the decoded HTML.
	for casing := 0; casing < 16; casing++ {
		attribute := []byte("href")
		for i := range attribute {
			if casing&(1<<i) != 0 {
				attribute[i] -= 'a' - 'A'
			}
		}
		for _, space := range []string{" ", "\t", "\n", "\r", "\f"} {
			for _, scheme := range []string{"http://", "https://", "//", "HtTp://", "HTTPS://"} {
				for _, quote := range []string{`"`, `'`, ``} {
					for pad := 0; pad < 3; pad++ {
						decoded := strings.Repeat("x", pad) + "<a" + space + string(attribute) + "=" + quote + scheme + "example.com/pills" + quote + ">pills</a>"
						if !hasRule(scanner.ScanContent(echoBase64(decoded), ".php"), "spam_base64_links") {
							t.Errorf("no match for encoded %q", decoded)
						}
					}
				}
			}
		}
	}
}

func TestSpamBase64Links_LocalReferencesDoNotMatch(t *testing.T) {
	scanner := spamBase64Scanner(t)
	for _, target := range []string{"#logo", "/images/logo.svg", "http-help.html", "https-guide.html", "data:image/gif;base64,R0lGODlhAQAB"} {
		for pad := 0; pad < 3; pad++ {
			decoded := strings.Repeat("x", pad) + `<a href="` + target + `">help</a>`
			if hasRule(scanner.ScanContent(echoBase64(decoded), ".php"), "spam_base64_links") {
				t.Errorf("matched local reference %q", decoded)
			}
		}
	}
}

func TestSpamBase64Links_Base64CaseAndAlignment(t *testing.T) {
	scanner := spamBase64Scanner(t)
	for pad := 0; pad < 3; pad++ {
		encoded := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("x", pad) + `<a href="http://example.com/">pills</a>`))
		for _, phpQuote := range []string{`"`, `'`} {
			content := []byte("<?php ECHO BASE64_DECODE(" + phpQuote + encoded + phpQuote + ");")
			if !hasRule(scanner.ScanContent(content, ".php"), "spam_base64_links") {
				t.Fatal("PHP keyword folding must not be disabled with base64 folding")
			}
		}
		for _, altered := range []string{strings.ToLower(encoded), strings.ToUpper(encoded), "A" + encoded, "AA" + encoded, "AAA" + encoded} {
			// Re-encode valid binary so padding errors cannot explain silence.
			unpadded := strings.TrimRight(altered, "=")
			binary, err := base64.RawStdEncoding.DecodeString(unpadded + strings.Repeat("A", (4-len(unpadded)%4)%4))
			if err != nil {
				t.Fatal(err)
			}
			if hasRule(scanner.ScanContent(echoBase64(string(binary)), ".php"), "spam_base64_links") {
				t.Errorf("matched binary after changing base64 case or alignment: %q", altered)
			}
		}
	}
}

func TestSpamBase64Links_BoundaryBytes(t *testing.T) {
	scanner := spamBase64Scanner(t)
	// Partial sextets share bits with the adjacent bytes. Both printable and
	// binary neighbours must preserve the decoded attribute's exact bits.
	for adjacent := 0; adjacent < 256; adjacent++ {
		for pad := 0; pad < 3; pad++ {
			for _, quote := range []string{`"`, `'`, ``} {
				decoded := strings.Repeat(string([]byte{byte(adjacent)}), pad) + " href=" + quote + "http://" + string([]byte{byte(adjacent)})
				if !hasRule(scanner.ScanContent(echoBase64(decoded), ".php"), "spam_base64_links") {
					t.Errorf("no match beside byte %x at padding %d with quote %q", adjacent, pad, quote)
				}
			}
		}
	}
}

func TestSpamBase64Links_StableTokens(t *testing.T) {
	for _, tc := range []struct {
		decoded string
		tokens  [3]string
	}{
		{` href="http`, [3]string{"IGhyZWY9Imh0dH", "BocmVmPSJodHRw", "gaHJlZj0iaHR0c"}},
		{` href='http`, [3]string{"IGhyZWY9J2h0dH", "BocmVmPSdodHRw", "gaHJlZj0naHR0c"}},
		{` href=http`, [3]string{"IGhyZWY9aHR0c", "BocmVmPWh0dH", "gaHJlZj1odHRw"}},
	} {
		for pad, want := range tc.tokens {
			t.Run(fmt.Sprintf("%s/%d", tc.decoded, pad), func(t *testing.T) {
				encoded := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("x", pad) + tc.decoded))
				// Keep only sextets made entirely from the target's bits.
				got := encoded[(pad*8+5)/6 : (pad+len(tc.decoded))*8/6]
				if got != want {
					t.Fatalf("stable token = %q, want %q", got, want)
				}
			})
		}
	}
}

// A link can start at any byte of the decoded text, so its encoding takes one
// of three shapes. The leading filler moves it through all three.
func TestSpamBase64Links_EncodedLinkMatchesAtEveryAlignment(t *testing.T) {
	scanner := loadRepoScanner(t)
	for _, quote := range []string{`"`, `'`, ``} {
		for pad := 0; pad < 3; pad++ {
			decoded := strings.Repeat("x", pad) + `<a href=` + quote + `http://example.com/pills` + quote + `>pills</a>`
			if !hasRule(scanner.ScanContent(echoBase64(decoded), ".php"), "spam_base64_links") {
				t.Errorf("no match for encoded %q", decoded)
			}
		}
	}
}

func TestSpamBase64Links_LinkAfterOtherAttributesMatches(t *testing.T) {
	scanner := loadRepoScanner(t)
	decoded := `<div style="display:none"><a title="cheap" href="https://example.com/">cheap</a></div>`
	if !hasRule(scanner.ScanContent(echoBase64(decoded), ".php"), "spam_base64_links") {
		t.Errorf("no match for encoded %q", decoded)
	}
}

func TestSpamBase64Links_TrackingPixelDoesNotMatch(t *testing.T) {
	scanner := loadRepoScanner(t)
	content := []byte("<?php\nheader('Content-Type: image/gif');\necho base64_decode('R0lGODlhAQABAJAAAP8AAAAAACH5BAUQAAAALAAAAAABAAEAAAICBAEAOw==');\n")
	if hasRule(scanner.ScanContent(content, ".php"), "spam_base64_links") {
		t.Error("spam_base64_links matched a 1x1 tracking GIF")
	}
}

func TestSpamBase64Links_InlineSVGDoesNotMatch(t *testing.T) {
	scanner := loadRepoScanner(t)
	svg := `<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" viewBox="0 0 10 10">` +
		`<defs><path id="a" d="M0 0h10v10H0z"/></defs><use xlink:href="#a"/><use href="#a"/></svg>`
	for pad := 0; pad < 3; pad++ {
		decoded := strings.Repeat(" ", pad) + svg
		if hasRule(scanner.ScanContent(echoBase64(decoded), ".php"), "spam_base64_links") {
			t.Errorf("spam_base64_links matched an inline SVG logo (padding %d)", pad)
		}
	}
}
