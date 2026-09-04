package wpcheck

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
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
func stagedPackage(t *testing.T, dir, slug, mainName, version string, body []byte) (root, rel string) {
	t.Helper()
	root = filepath.Join(dir, "wp-content", "upgrade", slug+"."+version, slug)
	rel = filepath.Join("lite", "includes", "admin", "wp-site-health.php")
	if err := os.MkdirAll(filepath.Join(root, filepath.Dir(rel)), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, mainName), stagedPluginMain(version), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, rel), body, 0o644); err != nil {
		t.Fatal(err)
	}
	return root, rel
}

func stagedPluginMain(version string) []byte {
	return []byte("<?php\n/*\nPlugin Name: Staged\nVersion: " + version + "\n*/\n")
}

func TestIsVerifiedPluginFileAcceptsStagedUpgradePackage(t *testing.T) {
	dir := t.TempDir()
	const slug, version = "google-analytics-for-wordpress", "11.2.0"
	const mainName = "googleanalytics.php"
	body := []byte("<?php\nclass MonsterInsights_Site_Health {}\n")
	root, rel := stagedPackage(t, dir, slug, mainName, version, body)

	zipBytes := buildPluginZip(t, map[string][]byte{
		filepath.ToSlash(filepath.Join(slug, mainName)): stagedPluginMain(version),
		filepath.ToSlash(filepath.Join(slug, rel)):      body,
	})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(zipBytes)
	}))
	defer srv.Close()
	checksums, err := fetchPluginChecksumsFromURL(srv.URL+"/plugin.zip", slug)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := checksums[rel]; !ok {
		t.Fatalf("official ZIP checksums have no key for staged relative path %q", rel)
	}

	c := NewCache(t.TempDir())
	c.setPluginChecksums(slug, version, checksums)

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
	root, rel := stagedPackage(t, dir, slug, "googleanalytics.php", version, body)

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

func TestIsVerifiedPluginFileRejectsPayloadAppendedAfterHashLimit(t *testing.T) {
	dir := t.TempDir()
	const slug, version = "akismet", "5.5"
	officialBody := bytes.Repeat([]byte{'A'}, maxFileSize)
	stagedBody := append(append([]byte(nil), officialBody...), []byte("<?php system($_GET['c']); ?>")...)
	root, rel := stagedPackage(t, dir, slug, slug+".php", version, stagedBody)

	sum := sha256.Sum256(officialBody)
	c := NewCache(t.TempDir())
	c.setPluginChecksums(slug, version, map[string]string{rel: hex.EncodeToString(sum[:])})

	path := filepath.Join(root, rel)
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()

	if c.IsVerifiedPluginFile(int(f.Fd()), path) {
		t.Error("IsVerifiedPluginFile = true for an official-size prefix with an appended payload")
	}
}

// A staged-tree writer controls both the path and version header, but neither
// can turn matching bytes from a different manifest path into a verified file.
func TestIsVerifiedPluginFileRejectsForgedStagedManifestPath(t *testing.T) {
	dir := t.TempDir()
	const slug, forgedVersion = "akismet", "99.0"
	body := []byte("<?php\n// byte-for-byte official content at another path\n")
	root, rel := stagedPackage(t, dir, slug, slug+".php", forgedVersion, body)

	sum := sha256.Sum256(body)
	c := NewCache(t.TempDir())
	c.setPluginChecksums(slug, forgedVersion, map[string]string{
		filepath.Join("different", "official.php"): hex.EncodeToString(sum[:]),
	})

	path := filepath.Join(root, rel)
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()

	if c.IsVerifiedPluginFile(int(f.Fd()), path) {
		t.Error("IsVerifiedPluginFile = true for bytes absent from the staged file's manifest path")
	}
}

func TestIsVerifiedPluginFileRejectsThemeAndCoreStagingTrees(t *testing.T) {
	cases := []struct {
		name        string
		path        string
		version     string
		rootPHPName string
		rootPHPBody []byte
		body        []byte
	}{
		{
			name:        "theme",
			path:        filepath.Join("wp-content", "upgrade", "twentytwentyfive.1.4", "twentytwentyfive", "functions.php"),
			version:     "1.4",
			rootPHPName: "functions.php",
			rootPHPBody: []byte("<?php\n/* Theme Name: Twenty Twenty-Five\nVersion: 1.4\n*/\n"),
		},
		{
			name:        "core",
			path:        filepath.Join("wp-content", "upgrade", "wordpress-6.8.2", "wordpress", "wp-includes", "version.php"),
			version:     "6.8.2",
			rootPHPName: "wp-settings.php",
			rootPHPBody: []byte("<?php\n/* WordPress bootstrap\nVersion: 6.8.2\n*/\n"),
			body:        []byte("<?php\n$wp_version = '6.8.2';\n"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), tc.path)
			body := tc.body
			if body == nil {
				body = tc.rootPHPBody
			}
			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, body, 0o644); err != nil {
				t.Fatal(err)
			}
			root, slug := DetectPluginRoot(path)
			if root == "" || slug == "" {
				t.Fatal("test path did not reach staged root detection")
			}
			rootPHPPath := filepath.Join(root, tc.rootPHPName)
			if rootPHPPath != path {
				if err := os.WriteFile(rootPHPPath, tc.rootPHPBody, 0o644); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := ReadPluginVersion(root, slug); err == nil {
				t.Fatal("non-plugin staging tree supplied a plugin version")
			}
			f, err := os.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = f.Close() }()

			sum := sha256.Sum256(body)
			c := NewCache(t.TempDir())
			rel, err := filepath.Rel(root, path)
			if err != nil {
				t.Fatal(err)
			}
			c.setPluginChecksums(slug, tc.version, map[string]string{rel: hex.EncodeToString(sum[:])})
			if c.IsVerifiedPluginFile(int(f.Fd()), path) {
				t.Error("IsVerifiedPluginFile = true for a non-plugin staging tree")
			}
		})
	}
}

// The production case that motivated this: MonsterInsights ships as slug
// "google-analytics-for-wordpress" with its main file named
// googleanalytics.php, so the whole staged package must still verify.
func TestIsVerifiedPluginFileAcceptsStagedPackageWithAlternateMainFile(t *testing.T) {
	dir := t.TempDir()
	const slug, version = "google-analytics-for-wordpress", "11.2.0"
	body := []byte("<?php\nclass MonsterInsights_Site_Health {}\n")
	root, rel := stagedPackage(t, dir, slug, "googleanalytics.php", version, body)

	sum := sha256.Sum256(body)
	c := NewCache(t.TempDir())
	c.setPluginChecksums(slug, version, map[string]string{rel: hex.EncodeToString(sum[:])})

	f, err := os.Open(filepath.Join(root, rel))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()

	if !c.IsVerifiedPluginFile(int(f.Fd()), filepath.Join(root, rel)) {
		t.Error("IsVerifiedPluginFile = false, want true when the main file name differs from the slug")
	}
}
