package checks

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// checkIframePhishing analyses tiny HTML files for fullscreen-iframe
// phishing redirectors. Returns a summary string when suspicious, empty
// otherwise.

func writeHTML(t *testing.T, content string) string {
	t.Helper()
	tmp := t.TempDir()
	p := filepath.Join(tmp, "page.html")
	if err := os.WriteFile(p, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestCheckIframePhishingMissingFileReturnsEmpty(t *testing.T) {
	if got := checkIframePhishing("/no-such-file"); got != "" {
		t.Errorf("missing file should return empty, got %q", got)
	}
}

func TestCheckIframePhishingEmptyFileReturnsEmpty(t *testing.T) {
	if got := checkIframePhishing(writeHTML(t, "")); got != "" {
		t.Errorf("empty file should return empty, got %q", got)
	}
}

func TestCheckIframePhishingNoIframeTagReturnsEmpty(t *testing.T) {
	html := "<!doctype html><html><body>just text, no iframe</body></html>"
	if got := checkIframePhishing(writeHTML(t, html)); got != "" {
		t.Errorf("no iframe should return empty, got %q", got)
	}
}

func TestCheckIframePhishingIframeWithoutSrcReturnsEmpty(t *testing.T) {
	html := "<html><body><iframe width=\"100%\" height=\"100%\"></iframe></body></html>"
	if got := checkIframePhishing(writeHTML(t, html)); got != "" {
		t.Errorf("iframe without src should return empty, got %q", got)
	}
}

func TestCheckIframePhishingIframeLocalSrcReturnsEmpty(t *testing.T) {
	// Local (non-external) src → not flagged.
	html := `<html><body><iframe src="/local.html" width="100%" height="100%"></iframe></body></html>`
	if got := checkIframePhishing(writeHTML(t, html)); got != "" {
		t.Errorf("local src iframe should return empty, got %q", got)
	}
}

func TestCheckIframePhishingExternalFullscreenIframeFlagged(t *testing.T) {
	// External URL + fullscreen (100%) → should be flagged.
	html := `<html><body><iframe src="https://evil.example.com/phish" width="100%" height="100%" style="position:fixed;top:0;left:0"></iframe></body></html>`
	got := checkIframePhishing(writeHTML(t, html))
	if got == "" {
		t.Fatalf("external fullscreen iframe should be flagged")
	}
	if !strings.Contains(got, "evil.example.com") {
		t.Errorf("result should name the external host: %q", got)
	}
}

func TestCheckIframePhishingIframeWithBadQuoteReturnsEmpty(t *testing.T) {
	// src attribute with no quote at all — parser requires ' or " to
	// delimit the URL.
	html := "<html><body><iframe src=https://evil.example.com></iframe></body></html>"
	if got := checkIframePhishing(writeHTML(t, html)); got != "" {
		t.Errorf("unquoted src should return empty, got %q", got)
	}
}

func TestCheckIframePhishingIframeMalformedNoCloseReturnsEmpty(t *testing.T) {
	// Open <iframe tag with no closing > — function bails.
	html := "<html><body><iframe src=\"https://evil.example.com"
	if got := checkIframePhishing(writeHTML(t, html)); got != "" {
		t.Errorf("malformed iframe should return empty, got %q", got)
	}
}

func TestCheckIframePhishingSingleQuotedExternalSrc(t *testing.T) {
	html := `<html><body><iframe src='https://evil.example.com/x' style="width:100%;height:100%"></iframe></body></html>`
	got := checkIframePhishing(writeHTML(t, html))
	if got == "" {
		t.Fatalf("single-quoted external src should still be parsed")
	}
	if !strings.Contains(got, "evil.example.com") {
		t.Errorf("host not captured: %q", got)
	}
}
