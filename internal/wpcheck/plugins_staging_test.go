package wpcheck

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

// WordPress unpacks a plugin update into wp-content/upgrade/<package>/<slug>/
// before moving it into place. Every PHP file in that tree used to miss plugin
// verification, so a routine update opened one warning per file.
func TestDetectPluginRootRecognizesUpgradeStaging(t *testing.T) {
	const base = "/home/alice/public_html/wp-content/upgrade/google-analytics-for-wordpress.11.2.0/google-analytics-for-wordpress"
	root, slug := DetectPluginRoot(base + "/lite/includes/admin/wp-site-health.php")
	if root != base {
		t.Errorf("root = %q, want %q", root, base)
	}
	if slug != "google-analytics-for-wordpress" {
		t.Errorf("slug = %q, want %q", slug, "google-analytics-for-wordpress")
	}
}

func TestDetectPluginRootStagingRejectsMalformedPaths(t *testing.T) {
	cases := []struct {
		name string
		path string
	}{
		{"no slug directory", "/home/alice/public_html/wp-content/upgrade/pkg.1.0/plugin.php"},
		{"empty package", "/home/alice/public_html/wp-content/upgrade//slug/file.php"},
		{"empty slug", "/home/alice/public_html/wp-content/upgrade/pkg.1.0//file.php"},
		{"dot package", "/home/alice/public_html/wp-content/upgrade/./slug/file.php"},
		{"dotdot package", "/home/alice/public_html/wp-content/upgrade/../slug/file.php"},
		{"dot slug", "/home/alice/public_html/wp-content/upgrade/pkg.1.0/./file.php"},
		{"dotdot slug", "/home/alice/public_html/wp-content/upgrade/pkg.1.0/../file.php"},
		{"no file after slug", "/home/alice/public_html/wp-content/upgrade/pkg.1.0/slug"},
		{"unrelated upgrade dir", "/home/alice/public_html/upgrade/pkg.1.0/slug/file.php"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if root, slug := DetectPluginRoot(tc.path); root != "" || slug != "" {
				t.Errorf("DetectPluginRoot() = (%q, %q), want empty", root, slug)
			}
		})
	}
}

// An installed plugin still resolves through the plugins directory, and that
// reading wins when a path somehow contains both segments.
func TestDetectPluginRootPrefersInstalledPluginDirectory(t *testing.T) {
	const path = "/home/alice/public_html/wp-content/plugins/akismet/wp-content/upgrade/pkg.1.0/other/file.php"
	root, slug := DetectPluginRoot(path)
	if want := "/home/alice/public_html/wp-content/plugins/akismet"; root != want {
		t.Errorf("root = %q, want %q", root, want)
	}
	if slug != "akismet" {
		t.Errorf("slug = %q, want %q", slug, "akismet")
	}
}

func TestDetectPluginRootRejectsRelativeInstalledSlug(t *testing.T) {
	for _, slug := range []string{".", ".."} {
		path := "/home/alice/public_html/wp-content/plugins/" + slug + "/file.php"
		if root, got := DetectPluginRoot(path); root != "" || got != "" {
			t.Errorf("DetectPluginRoot(%q) = (%q, %q), want empty", path, root, got)
		}
	}
}

// stagedPackage writes a plugin package under an upgrade staging tree and
// returns the staged root plus the relative path of the extra file it wrote.
func stagedPackage(t *testing.T, dir, slug, version string, body []byte) (root, rel string) {
	t.Helper()
	root = filepath.Join(dir, "wp-content", "upgrade", slug+"."+version, slug)
	rel = filepath.Join("lite", "includes", "admin", "wp-site-health.php")
	if err := os.MkdirAll(filepath.Join(root, filepath.Dir(rel)), 0o755); err != nil {
		t.Fatal(err)
	}
	main := "<?php\n/*\nPlugin Name: Staged\nVersion: " + version + "\n*/\n"
	if err := os.WriteFile(filepath.Join(root, slug+".php"), []byte(main), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, rel), body, 0o644); err != nil {
		t.Fatal(err)
	}
	return root, rel
}

func TestIsVerifiedPluginFileAcceptsStagedUpgradePackage(t *testing.T) {
	dir := t.TempDir()
	const slug, version = "google-analytics-for-wordpress", "11.2.0"
	body := []byte("<?php\nclass MonsterInsights_Site_Health {}\n")
	root, rel := stagedPackage(t, dir, slug, version, body)

	sum := sha256.Sum256(body)
	c := NewCache(t.TempDir())
	c.setPluginChecksums(slug, version, map[string]string{rel: hex.EncodeToString(sum[:])})

	f, err := os.Open(filepath.Join(root, rel))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()

	if !c.IsVerifiedPluginFile(int(f.Fd()), filepath.Join(root, rel)) {
		t.Error("IsVerifiedPluginFile = false, want true for a staged file matching the official hash")
	}
}

// Verification stays per-file and content-based: a payload dropped into a
// staging tree has no entry in the official manifest and is never verified.
func TestIsVerifiedPluginFileRejectsTamperedStagedFile(t *testing.T) {
	dir := t.TempDir()
	const slug, version = "google-analytics-for-wordpress", "11.2.0"
	body := []byte("<?php\nclass MonsterInsights_Site_Health {}\n")
	root, rel := stagedPackage(t, dir, slug, version, body)

	sum := sha256.Sum256([]byte("<?php\n// the official bytes\n"))
	c := NewCache(t.TempDir())
	c.setPluginChecksums(slug, version, map[string]string{rel: hex.EncodeToString(sum[:])})

	f, err := os.Open(filepath.Join(root, rel))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()

	if c.IsVerifiedPluginFile(int(f.Fd()), filepath.Join(root, rel)) {
		t.Error("IsVerifiedPluginFile = true, want false for a staged file whose bytes differ")
	}
}
