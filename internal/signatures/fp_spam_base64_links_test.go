package signatures

import (
	"encoding/base64"
	"strings"
	"testing"
)

// spam_base64_links targets hidden links echoed from a base64 literal. Plugins
// and themes echo base64 literals that are images too: a newsletter plugin's
// 1x1 open-tracking GIF, an inline SVG logo. Only a literal that decodes to a
// link pointing at another site is the spam shape.

func echoBase64(decoded string) []byte {
	return []byte("<?php\necho base64_decode('" + base64.StdEncoding.EncodeToString([]byte(decoded)) + "');\n")
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
