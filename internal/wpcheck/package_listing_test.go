package wpcheck

import (
	"crypto/md5" // #nosec G501 -- wordpress.org publishes MD5 digests for core files
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
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

func coreVersionFile(version string) string {
	return "<?php\n$wp_version = '" + version + "';\n"
}

func md5Hex(s string) string {
	sum := md5.Sum([]byte(s)) // #nosec G401 -- matches the published core digests
	return hex.EncodeToString(sum[:])
}

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// coreInstall writes an install whose version.php is the release's own copy,
// and caches that release's manifest when c is set.
func coreInstall(t *testing.T, c *Cache, version string, files ...string) string {
	t.Helper()
	root := filepath.Join(t.TempDir(), "public_html")
	writeListingFile(t, filepath.Join(root, "wp-includes", "version.php"), coreVersionFile(version))
	if c != nil {
		checksums := map[string]string{"wp-includes/version.php": md5Hex(coreVersionFile(version))}
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
		{"wp-includes/Text/Diff/Renderer/index.php", false, true},
		{"wp-admin/includes/x.php", false, true},
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

// A core update rewrites version.php before the new files land. A file is
// judged against the release version.php names now, and only once that
// release's own version.php is cached to vouch for it.
func TestPackageListingFollowsAChangedVersion(t *testing.T) {
	c := stoppedCache(t)
	root := coreInstall(t, c, "6.9.4")
	path := filepath.Join(root, "wp-includes", "new-in-7.php")
	writeListingFile(t, path, "<?php")
	if listed, known := c.PackageListing(path); listed || !known {
		t.Fatalf("absent from an authentic release: listed=%t known=%t, want known absent", listed, known)
	}
	writeListingFile(t, filepath.Join(root, "wp-includes", "version.php"), coreVersionFile("7.0"))
	if listed, known := c.PackageListing(path); listed || known {
		t.Fatalf("after a version change: listed=%t known=%t, want unknown until 7.0 is cached", listed, known)
	}
	if err := c.PersistChecksums("7.0", "en_US", []byte(`{}`), map[string]string{
		"wp-includes/version.php":  md5Hex(coreVersionFile("7.0")),
		"wp-includes/new-in-7.php": "x",
	}); err != nil {
		t.Fatal(err)
	}
	if listed, known := c.PackageListing(path); !listed || !known {
		t.Fatalf("with 7.0 cached: listed=%t known=%t, want listed", listed, known)
	}
}

// version.php and plugin headers are written by the account. A header that
// is not the release's own copy cannot vouch for what the release ships.
func TestPackageListingNeedsAnAuthenticHeader(t *testing.T) {
	c := stoppedCache(t)
	root := coreInstall(t, c, "6.9.4", "wp-includes/load.php")
	writeListingFile(t, filepath.Join(root, "wp-includes", "version.php"), coreVersionFile("6.9.4")+"// edited\n")
	path := filepath.Join(root, "wp-includes", "planted.php")
	writeListingFile(t, path, "<?php")
	if listed, known := c.PackageListing(path); listed || known {
		t.Fatalf("edited version.php: listed=%t known=%t, want unknown", listed, known)
	}

	plugin := filepath.Join(t.TempDir(), "wp-content", "plugins", "test-plugin")
	main := "<?php\n/*\nPlugin Name: Test\nVersion: 1.0.0\n*/\n"
	writeListingFile(t, filepath.Join(plugin, "test-plugin.php"), main+"// edited\n")
	c.setPluginChecksums("test-plugin", "1.0.0", map[string]string{"test-plugin.php": sha256Hex(main)})
	planted := filepath.Join(plugin, "inc", "planted.php")
	writeListingFile(t, planted, "<?php")
	if listed, known := c.PackageListing(planted); listed || known {
		t.Fatalf("edited plugin header: listed=%t known=%t, want unknown", listed, known)
	}
}

func TestPackageListingPlugins(t *testing.T) {
	c := stoppedCache(t)
	root := filepath.Join(t.TempDir(), "wp-content", "plugins", "test-plugin")
	main := "<?php\n/*\nPlugin Name: Test\nVersion: 1.0.0\n*/\n"
	writeListingFile(t, filepath.Join(root, "test-plugin.php"), main)
	c.setPluginChecksums("test-plugin", "1.0.0", map[string]string{"test-plugin.php": sha256Hex(main), "inc/a.php": "x"})

	for rel, want := range map[string]bool{"test-plugin.php": true, "inc/a.php": true, "inc/planted.php": false} {
		path := filepath.Join(root, rel)
		if rel != "test-plugin.php" {
			writeListingFile(t, path, "<?php")
		}
		if listed, known := c.PackageListing(path); listed != want || !known {
			t.Errorf("%s: listed=%t known=%t, want %t true", rel, listed, known, want)
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

// Outside core's own directories and installed plugins, a manifest says
// nothing about a file: sites add their own there.
func TestPackageListingAbsenceOutsidePackagesIsUnknown(t *testing.T) {
	c := stoppedCache(t)
	root := coreInstall(t, c, "6.9.4")
	for _, rel := range []string{
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
		t.Fatalf("plugin header the release does not vouch for: listed=%t known=%t, want unknown", listed, known)
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

func TestPackageListingPluginHeaderScope(t *testing.T) {
	for _, name := range []string{"non-slug main", "late header"} {
		t.Run(name, func(t *testing.T) {
			c := stoppedCache(t)
			root := filepath.Join(t.TempDir(), "wp-content/plugins/test-plugin")
			main := "<?php\n/*\nPlugin Name: Test\nVersion: 1.0.0\n*/\n"
			filename := "main.php"
			if name == "late header" {
				filename = "test-plugin.php"
				main = strings.Repeat(" ", pluginHeaderReadLimit) + main
			}
			writeListingFile(t, filepath.Join(root, filename), main)
			c.setPluginChecksums("test-plugin", "1.0.0", map[string]string{filename: sha256Hex(main)})
			if listed, known := c.PackageListing(filepath.Join(root, "extra.php")); listed || known {
				t.Fatalf("listed=%t known=%t, want unknown", listed, known)
			}
		})
	}
}

// Each cache state either lists the candidate or cannot authenticate the
// header. Combining the two states must never authorize removal.
func TestPackageListingUsesOneManifest(t *testing.T) {
	for _, plugin := range []bool{false, true} {
		t.Run(map[bool]string{false: "core", true: "plugin"}[plugin], func(t *testing.T) {
			c := stoppedCache(t)
			root := coreInstall(t, c, "6.9.4")
			path := filepath.Join(root, "wp-includes/extra.php")
			key := cacheKey("6.9.4", "en_US")
			manifests := c.checksums
			authentic := map[string]string{"wp-includes/version.php": md5Hex(coreVersionFile("6.9.4")), "wp-includes/extra.php": "x"}
			if plugin {
				root = filepath.Join(t.TempDir(), "wp-content/plugins/test-plugin")
				main := "<?php\n/*\nPlugin Name: Test\nVersion: 1.0.0\n*/\n"
				writeListingFile(t, filepath.Join(root, "test-plugin.php"), main)
				path = filepath.Join(root, "extra.php")
				key = pluginKey("test-plugin", "1.0.0")
				manifests = c.pluginChecksums
				authentic = map[string]string{"test-plugin.php": sha256Hex(main), "extra.php": "x"}
			}
			manifests[key] = authentic
			unavailable := map[string]string{}
			stop := make(chan struct{})
			var wg sync.WaitGroup
			wg.Go(func() {
				for {
					select {
					case <-stop:
						return
					default:
					}
					c.mu.Lock()
					manifests[key] = authentic
					c.mu.Unlock()
					c.mu.Lock()
					manifests[key] = unavailable
					c.mu.Unlock()
				}
			})
			defer func() { close(stop); wg.Wait() }()
			for i := 0; i < 2000; i++ {
				if listed, known := c.PackageListing(path); known && !listed {
					t.Fatal("mixed cache states authorized removal")
				}
			}
		})
	}
}

func TestAuthenticHeaderReadBoundaries(t *testing.T) {
	for _, size := range []int{0, authenticHeaderMax - 1, authenticHeaderMax, authenticHeaderMax + 1} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "header.php")
			content := strings.Repeat("x", size)
			writeListingFile(t, path, content)
			data, ok := readAuthenticHeader(path)
			if want := size <= authenticHeaderMax; ok != want {
				t.Fatalf("read accepted=%t, want %t", ok, want)
			}
			if ok && string(data) != content {
				t.Fatal("header was not read whole")
			}
		})
	}
}
