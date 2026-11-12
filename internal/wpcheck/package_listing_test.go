package wpcheck

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func writeListingFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// stoppedCache never starts a background fetch, so a cache miss stays one.
func stoppedCache(t *testing.T) *Cache {
	t.Helper()
	c := NewCache(t.TempDir())
	stop := make(chan struct{})
	close(stop)
	c.SetStopCh(stop)
	return c
}

func coreInstall(t *testing.T, c *Cache, version string, files ...string) string {
	t.Helper()
	root := filepath.Join(t.TempDir(), "public_html")
	writeListingFile(t, filepath.Join(root, "wp-includes", "version.php"), "<?php\n$wp_version = '"+version+"';\n")
	if c != nil {
		checksums := map[string]string{"wp-includes/version.php": "x"}
		for _, f := range files {
			checksums[f] = "x"
		}
		if err := c.PersistChecksums(version, "en_US", []byte(`{}`), checksums); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func TestPackageListingCoreDirectories(t *testing.T) {
	c := stoppedCache(t)
	root := coreInstall(t, c, "6.9.4", "wp-includes/load.php", "wp-admin/index.php")
	cases := []struct {
		rel          string
		listed, know bool
	}{
		{"wp-includes/load.php", true, true},
		{"wp-admin/index.php", true, true},
		{"wp-includes/Text/Diff/Renderer/index.php", false, false},
		{"wp-admin/includes/x.php", false, false},
		// Core does not own the install's root or wp-content: users and
		// plugins add files there.
		{"custom.php", false, false},
		{"wp-content/themes/site/functions.php", false, false},
	}
	for _, tc := range cases {
		path := filepath.Join(root, tc.rel)
		writeListingFile(t, path, "<?php")
		listed, known := c.PackageListing(path)
		if listed != tc.listed || known != tc.know {
			t.Errorf("%s: listed=%t known=%t, want %t %t", tc.rel, listed, known, tc.listed, tc.know)
		}
	}
}

func TestPackageListingUnknownWithoutCachedRelease(t *testing.T) {
	c := stoppedCache(t)
	root := coreInstall(t, nil, "6.9.4")
	path := filepath.Join(root, "wp-includes", "planted.php")
	writeListingFile(t, path, "<?php")
	if listed, known := c.PackageListing(path); listed || known {
		t.Fatalf("no cached release: listed=%t known=%t, want unknown", listed, known)
	}
	missing := filepath.Join(t.TempDir(), "public_html", "wp-includes", "x.php")
	writeListingFile(t, missing, "<?php")
	if listed, known := c.PackageListing(missing); listed || known {
		t.Fatalf("no version.php: listed=%t known=%t, want unknown", listed, known)
	}
}

// A core update rewrites version.php before the new files land. A file the
// cached release does not list may belong to the release now declared.
func TestPackageListingRereadsAChangedVersion(t *testing.T) {
	c := stoppedCache(t)
	root := coreInstall(t, c, "6.9.4")
	path := filepath.Join(root, "wp-includes", "new-in-7.php")
	writeListingFile(t, path, "<?php")
	if listed, known := c.PackageListing(path); listed || known {
		t.Fatal("absent file must remain unknown")
	}
	writeListingFile(t, filepath.Join(root, "wp-includes", "version.php"), "<?php\n$wp_version = '7.0';\n")
	if listed, known := c.PackageListing(path); listed || known {
		t.Fatalf("after a version change: listed=%t known=%t, want unknown until 7.0 is cached", listed, known)
	}
	if err := c.PersistChecksums("7.0", "en_US", []byte(`{}`), map[string]string{"wp-includes/new-in-7.php": "x"}); err != nil {
		t.Fatal(err)
	}
	if listed, known := c.PackageListing(path); !listed || !known {
		t.Fatalf("with 7.0 cached: listed=%t known=%t, want listed", listed, known)
	}
}

func TestPackageListingPlugins(t *testing.T) {
	c := stoppedCache(t)
	root := filepath.Join(t.TempDir(), "wp-content", "plugins", "test-plugin")
	writeListingFile(t, filepath.Join(root, "test-plugin.php"), "<?php\n/*\nPlugin Name: Test\nVersion: 1.0.0\n*/\n")
	c.setPluginChecksums("test-plugin", "1.0.0", map[string]string{"test-plugin.php": "x", "inc/a.php": "x"})

	for rel, want := range map[string]bool{"test-plugin.php": true, "inc/a.php": true, "inc/planted.php": false} {
		path := filepath.Join(root, rel)
		if rel != "test-plugin.php" {
			writeListingFile(t, path, "<?php")
		}
		if listed, known := c.PackageListing(path); listed != want || known != want {
			t.Errorf("%s: listed=%t known=%t, want %t %t", rel, listed, known, want, want)
		}
	}

	premium := filepath.Join(t.TempDir(), "wp-content", "plugins", "premium")
	writeListingFile(t, filepath.Join(premium, "premium.php"), "<?php\n/*\nPlugin Name: P\nVersion: 2.0\n*/\n")
	c.markPluginNotFound("premium", "2.0", pluginNotFoundTTL)
	if listed, known := c.PackageListing(filepath.Join(premium, "premium.php")); listed || known {
		t.Fatalf("plugin without published checksums: listed=%t known=%t, want unknown", listed, known)
	}
}

func TestPackageListingThemesAreUnknown(t *testing.T) {
	c := stoppedCache(t)
	root := coreInstall(t, c, "6.9.4")
	theme := filepath.Join(root, "wp-content", "themes", "hello")
	writeListingFile(t, filepath.Join(theme, "style.css"), "/*\nTheme Name: Hello\nVersion: 1.0\n*/\n")
	path := filepath.Join(theme, "modules", "a", "b", "index.php")
	writeListingFile(t, path, "<?php")
	if listed, known := c.PackageListing(path); listed || known {
		t.Fatalf("theme file: listed=%t known=%t, want unknown", listed, known)
	}
}

// A missing manifest entry is not evidence that a tenant file has no site
// code: updates can copy files before replacing their version header, and
// local extensions need not be present in the upstream archive.
func TestPackageListingAbsenceIsUnknown(t *testing.T) {
	c := stoppedCache(t)
	root := coreInstall(t, c, "6.9.4")
	for _, rel := range []string{
		"wp-includes/new-release.php",
		"wp-content/themes/site/wp-includes/template.php",
		"wp-content/upgrade/core/wordpress/wp-includes/new-release.php",
		"custom.php",
	} {
		path := filepath.Join(root, rel)
		writeListingFile(t, path, "<?php echo 'site';")
		if listed, known := c.PackageListing(path); listed || known {
			t.Errorf("%s: listed=%t known=%t, want unknown", rel, listed, known)
		}
	}
	plugin := filepath.Join(root, "wp-content/plugins/test-plugin")
	writeListingFile(t, filepath.Join(plugin, "test-plugin.php"), "<?php\n/*\nPlugin Name: Test\nVersion: 1.0.0\n*/\n")
	c.setPluginChecksums("test-plugin", "1.0.0", map[string]string{"test-plugin.php": "x"})
	path := filepath.Join(plugin, "extension.php")
	writeListingFile(t, path, "<?php echo 'site';")
	if listed, known := c.PackageListing(path); listed || known {
		t.Fatalf("tenant-controlled plugin identity: listed=%t known=%t, want unknown", listed, known)
	}
}

func TestPackageListingRejectsStagedAndIncompleteReleases(t *testing.T) {
	c := stoppedCache(t)
	root := coreInstall(t, c, "6.9.4", "wp-includes/load.php")
	path := filepath.Join(root, "wp-includes/load.php")
	if listed, known := c.PackageListing(path); !listed || !known {
		t.Fatal("setup: installed file must be listed")
	}
	writeListingFile(t, filepath.Join(root, "wp-includes/version.php"), "<?php\n$wp_version = '")
	if listed, known := c.PackageListing(path); listed || known {
		t.Fatal("partial version header reused a cached installation version")
	}
	staged := filepath.Join(root, "wp-content/upgrade/core/wordpress")
	writeListingFile(t, filepath.Join(staged, "wp-includes/version.php"), "<?php\n$wp_version = '6.9.4';\n")
	path = filepath.Join(staged, "wp-includes/load.php")
	if v := c.Describe(path); !v.Staged || v.Verdict != VerdictReady {
		t.Fatalf("setup: expected a cached staged release: %+v", v)
	}
	if listed, known := c.PackageListing(path); listed || known {
		t.Fatal("staged core file treated as installed")
	}
	plugin := filepath.Join(root, "wp-content/upgrade/test-plugin.1/test-plugin")
	writeListingFile(t, filepath.Join(plugin, "test-plugin.php"), "<?php\n/*\nPlugin Name: Test\nVersion: 1.0.0\n*/\n")
	c.setPluginChecksums("test-plugin", "1.0.0", map[string]string{"test-plugin.php": "x"})
	path = filepath.Join(plugin, "test-plugin.php")
	if v := c.Describe(path); !v.Staged || v.Verdict != VerdictReady {
		t.Fatalf("setup: expected a cached staged plugin: %+v", v)
	}
	if listed, known := c.PackageListing(path); listed || known {
		t.Fatal("staged plugin file treated as installed")
	}
}

func TestPackageListingRejectsFIFOHeader(t *testing.T) {
	c := stoppedCache(t)
	root := t.TempDir()
	header := filepath.Join(root, "wp-includes/version.php")
	if err := os.MkdirAll(filepath.Dir(header), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mkfifo(header, 0o644); err != nil {
		t.Fatal(err)
	}
	done := make(chan [2]bool, 1)
	go func() {
		listed, known := c.PackageListing(filepath.Join(root, "wp-includes/template.php"))
		done <- [2]bool{listed, known}
	}()
	select {
	case result := <-done:
		if result != [2]bool{} {
			t.Fatalf("special header supplied release: %v", result)
		}
	case <-time.After(time.Second):
		writer, err := os.OpenFile(header, os.O_WRONLY|unix.O_NONBLOCK, 0)
		if err != nil {
			t.Fatal(err)
		}
		_ = writer.Close()
		<-done
		t.Fatal("release lookup blocked on a tenant-controlled header")
	}
}
