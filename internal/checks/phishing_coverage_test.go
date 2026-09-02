package checks

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

// The scanner accepted HTML files up to 100 KB but read only the first
// 16 KB, so a kit that opens with a large inline stylesheet (every modern
// brand template does) kept its form past the read window and was never
// analysed.
func TestAnalyzeHTMLForPhishingReadsWholeAcceptedFile(t *testing.T) {
	padding := "<style>\n" + strings.Repeat("/* brand theme */ .x{color:#000}\n", 700) + "</style>\n"
	padded := strings.Replace(officePhishHTML, "<head>", "<head>\n"+padding, 1)
	if len(padded) < 20000 || len(padded) > 100000 {
		t.Fatalf("fixture size %d outside the accepted window", len(padded))
	}
	path := filepath.Join(t.TempDir(), "verify.html")
	if err := os.WriteFile(path, []byte(padded), 0o600); err != nil {
		t.Fatal(err)
	}
	if res := analyzeHTMLForPhishing(path); res == nil {
		t.Fatal("kit with a 20 KB stylesheet before its form was not detected")
	}
}

// wp-admin, wp-includes and cache directories were pruned by name. Stock
// WordPress ships no login-form HTML pages there, so a kit dropped into
// wp-includes is exactly as anomalous as one under uploads, and attackers
// use those paths because scanners skip them.
func TestScanForPhishingReachesKitUnderCoreDirectories(t *testing.T) {
	root := t.TempDir()
	for _, sub := range []string{"wp-includes/js/tinymce/skins", "wp-admin/css/colors", "cache/page"} {
		dir := filepath.Join(root, sub)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		// Padded past the scanner's 3 KB acceptance floor, like the kits it targets.
		if err := os.WriteFile(filepath.Join(dir, "verify.html"), []byte(officePhishHTML+strings.Repeat(" ", 3500)), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	var findings []alert.Finding
	scanForPhishing(context.Background(), root, 8, "alice", &config.Config{}, &findings)
	found := map[string]bool{}
	for _, f := range findings {
		found[f.FilePath] = true
	}
	for _, sub := range []string{"wp-includes/js/tinymce/skins", "wp-admin/css/colors", "cache/page"} {
		if !found[filepath.Join(root, sub, "verify.html")] {
			t.Fatalf("kit under %s not reported; findings=%+v", sub, findings)
		}
	}
}
