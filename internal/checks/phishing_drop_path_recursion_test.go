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

// CHK-P03: CheckPhishing must recurse into the real-world phishing drop paths.
// wp-content/uploads (date-nested) and .well-known were excluded outright, so
// HTML kits dropped there were invisible to every detection layer. The scan
// depth must also be deep enough to reach uploads/YYYY/MM/kit/.

func hasPhishingCheck(findings []alert.Finding, name string) bool {
	for _, f := range findings {
		if f.Check == name {
			return true
		}
	}
	return false
}

func TestScanForPhishingReachesWpContentUploadsKit(t *testing.T) {
	root := t.TempDir()
	kitDir := filepath.Join(root, "wp-content", "uploads", "2026", "07", "kit")
	if err := os.MkdirAll(kitDir, 0755); err != nil {
		t.Fatal(err)
	}
	// Brand-impersonation kit (>=3KB) dropped in a WordPress uploads date folder.
	if err := os.WriteFile(filepath.Join(kitDir, "verify.html"),
		[]byte(officePhishHTML+strings.Repeat(" ", 3500)), 0600); err != nil {
		t.Fatal(err)
	}

	cfg := &config.Config{}
	var findings []alert.Finding
	scanForPhishing(context.Background(), root, phishingScanMaxDepth, "alice", cfg, &findings)

	if !hasPhishingCheck(findings, "phishing_page") {
		t.Fatalf("phishing kit under wp-content/uploads/2026/07/kit not detected (findings=%d)", len(findings))
	}
}

func TestScanForPhishingRecursesWellKnown(t *testing.T) {
	root := t.TempDir()
	dropDir := filepath.Join(root, ".well-known", "pki-validation")
	if err := os.MkdirAll(dropDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dropDir, "login.html"),
		[]byte(officePhishHTML+strings.Repeat(" ", 3500)), 0600); err != nil {
		t.Fatal(err)
	}

	cfg := &config.Config{}
	var findings []alert.Finding
	scanForPhishing(context.Background(), root, phishingScanMaxDepth, "alice", cfg, &findings)

	if !hasPhishingCheck(findings, "phishing_page") {
		t.Fatalf("phishing kit under .well-known not detected (findings=%d)", len(findings))
	}
}

// Cost guard: the heavy / transient dirs stay excluded so the scan does not
// walk node_modules or WP core.
func TestScanForPhishingStillSkipsHeavyDirs(t *testing.T) {
	for _, skip := range []string{"node_modules", "vendor", "wp-admin", "wp-includes", ".git"} {
		root := t.TempDir()
		dropDir := filepath.Join(root, skip, "nested")
		if err := os.MkdirAll(dropDir, 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dropDir, "verify.html"),
			[]byte(officePhishHTML+strings.Repeat(" ", 3500)), 0600); err != nil {
			t.Fatal(err)
		}
		cfg := &config.Config{}
		var findings []alert.Finding
		scanForPhishing(context.Background(), root, phishingScanMaxDepth, "alice", cfg, &findings)
		if hasPhishingCheck(findings, "phishing_page") {
			t.Errorf("heavy dir %q should be skipped but a page was scanned inside it", skip)
		}
	}
}

// The production scan depth must reach the canonical dated-uploads drop path.
func TestPhishingScanMaxDepthReachesDatedUploads(t *testing.T) {
	// public_html -> wp-content -> uploads -> YYYY -> MM -> kit -> file:
	// six directory levels below the doc root.
	if phishingScanMaxDepth < 6 {
		t.Fatalf("phishingScanMaxDepth = %d, too shallow to reach wp-content/uploads/YYYY/MM/kit/", phishingScanMaxDepth)
	}
}
