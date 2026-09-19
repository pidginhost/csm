package checks

import (
	"archive/zip"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// A site backup can nest its document root under several directories, so
// wp-config.php is not always within two path components of the archive root.
// Bounding the depth outright loses those backups; accepting any depth flags
// plugin bundles that ship a wp-config.php fixture. The archive is classified
// on the pair instead: a deep config counts once the archive also carries the
// WordPress runtime that a fixture directory never contains.
func TestArchiveDeepConfigNeedsWordPressTree(t *testing.T) {
	root := t.TempDir()
	cases := []struct {
		name    string
		entries []string
		want    bool
	}{
		{
			name:    "deep-config-with-wp-tree.zip",
			entries: []string{"backup/2024/site/wp-config.php", "backup/2024/site/wp-load.php"},
			want:    true,
		},
		{
			name:    "deep-config-with-wp-includes.zip",
			entries: []string{"a/b/c/wp-config.php", "a/b/c/wp-includes/version.php"},
			want:    true,
		},
		// The false positive the depth bound exists to prevent: a plugin that
		// ships a configuration fixture but none of the WordPress runtime.
		{
			name:    "plugin-fixture.zip",
			entries: []string{"some-plugin/some-plugin.php", "some-plugin/tests/fixtures/wp-config.php"},
			want:    false,
		},
		// Shallow config keeps working without any structural marker.
		{
			name:    "shallow-config.zip",
			entries: []string{"snapshot-2024/wp-config.php"},
			want:    true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := filepath.Join(root, tc.name)
			writeZip(t, p, tc.entries...)
			if got := archiveHoldsSiteBackup(p); got != tc.want {
				t.Errorf("archiveHoldsSiteBackup(%s) = %v, want %v", tc.name, got, tc.want)
			}
		})
	}
}

func TestArchiveJoomlaPairRequiresSameDirectory(t *testing.T) {
	for _, tc := range []struct {
		name, config, runtime string
		want                  bool
	}{
		{"case-distinct", "Site/configuration.php", "site/includes/defines.php", false},
		{"space-distinct", " site/configuration.php", "site/administrator/index.php", false},
		{"same-case", "Site/configuration.php", "Site/includes/defines.php", true},
		{"same-space", " site/configuration.php", " site/administrator/index.php", true},
		{"dot-prefix", "./Site/configuration.php", "Site/includes/defines.php", true},
		{"backslashes", `Site\configuration.php`, `Site\includes\defines.php`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "bundle.zip")
			writeZip(t, p, tc.config, tc.runtime)
			if holds, complete := archiveSiteBackupStatus(context.Background(), p); holds != tc.want || !complete {
				t.Fatalf("archive status = (%v, %v), want (%v, true)", holds, complete, tc.want)
			}
		})
	}
}

func TestArchiveJoomlaPairRequiresFiles(t *testing.T) {
	for _, marker := range []string{"site/configuration.php", "site/includes/defines.php", "site/administrator/index.php"} {
		for _, tc := range []struct {
			name, suffix string
			mode         os.FileMode
		}{
			{"directory-attributes", "", os.ModeDir | 0o755},
			{"directory-slash", "/", 0o755},
			{"directory-backslash", `\`, 0o755},
			{"symlink", "", os.ModeSymlink | 0o777},
		} {
			t.Run(marker+"/"+tc.name, func(t *testing.T) {
				p := filepath.Join(t.TempDir(), "bundle.zip")
				f, err := os.Create(p)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = f.Close() })
				zw := zip.NewWriter(f)
				peer := "site/configuration.php"
				if marker == peer {
					peer = "site/includes/defines.php"
				}
				if _, err := zw.Create(peer); err != nil {
					t.Fatal(err)
				}
				header := &zip.FileHeader{Name: marker + tc.suffix}
				header.SetMode(tc.mode)
				// Cover attributes as well as the conventional trailing slash:
				// directory entries need not carry both.
				if _, err := zw.CreateHeader(header); err != nil {
					t.Fatal(err)
				}
				if err := zw.Close(); err != nil {
					t.Fatal(err)
				}
				if holds, complete := archiveSiteBackupStatus(context.Background(), p); holds || !complete {
					t.Fatalf("archive status = (%v, %v), want (false, true)", holds, complete)
				}
			})
		}
	}
}

func TestExposedArchiveJoomlaPairing(t *testing.T) {
	root := t.TempDir()
	entries := []string{"example.com/configuration.php", "example.com/includes/defines.php", "example.com/administrator/index.php"}
	writeZip(t, filepath.Join(root, "example.com.zip"), entries...)
	writeZip(t, filepath.Join(root, "blocked.zip"), entries...)
	writeZip(t, filepath.Join(root, "extension.zip"), "extension/configuration.php")
	writeZip(t, filepath.Join(root, "bundle.zip"), "Extension/configuration.php", "extension/includes/defines.php")
	probe := &fakeProbe{byPath: map[string]probeResult{
		"/example.com.zip": {status: 200, contentType: "application/zip", reachable: true},
		"/blocked.zip":     {status: 403, reachable: true},
		"/extension.zip":   {status: 200, contentType: "application/zip", reachable: true},
		"/bundle.zip":      {status: 200, contentType: "application/zip", reachable: true},
	}}
	withFakeProbe(t, probe)
	findings := scanVhostsForExposure(context.Background(), []vhost{{
		domain: "example.com", docroot: root, ip: "192.0.2.10",
	}}, nil)
	if len(findings) != 1 || findings[0].Check != "web_exposed_backup_archive" || findings[0].FilePath != filepath.Join(root, "example.com.zip") {
		t.Fatalf("expected only the reachable Joomla site archive, got %+v", findings)
	}
	if !probe.seen["/blocked.zip"] || probe.seen["/extension.zip"] || probe.seen["/bundle.zip"] {
		t.Fatalf("unexpected archive probes: %v", probe.seen)
	}
}

func TestArchiveJoomlaRetainsPairBeforeCancellation(t *testing.T) {
	for _, reverse := range []bool{false, true} {
		t.Run(fmt.Sprint(reverse), func(t *testing.T) {
			names := []string{"site/configuration.php", "site/includes/defines.php"}
			if reverse {
				names[0], names[1] = names[1], names[0]
			}
			for i := len(names); i < 257; i++ {
				names = append(names, fmt.Sprintf("assets/%03d.dat", i))
			}
			p := filepath.Join(t.TempDir(), "site.zip")
			writeZip(t, p, names...)
			ctx := &cancelOnSecondErrContext{Context: context.Background()}
			if holds, complete := archiveSiteBackupStatus(ctx, p); !holds || complete {
				t.Fatalf("cancelled archive status = (%v, %v), want (true, false)", holds, complete)
			}
		})
	}
}

// A Joomla backup usually nests its site under a directory named after the
// domain, so configuration.php sits one level down. A bare configuration.php at
// that depth is also what extension bundles ship, so it only counts when the
// same directory carries a Joomla entry point that no extension packages.
func TestArchiveNestedJoomlaConfigNeedsJoomlaTree(t *testing.T) {
	root := t.TempDir()
	cases := []struct {
		name    string
		entries []string
		want    bool
	}{
		{
			name:    "joomla-site-under-domain-dir.zip",
			entries: []string{"example.com/configuration.php", "example.com/includes/defines.php"},
			want:    true,
		},
		{
			name:    "joomla-site-admin-entry-point.zip",
			entries: []string{"example.com/administrator/index.php", "example.com/configuration.php"},
			want:    true,
		},
		{
			name:    "joomla-site-deeply-nested.zip",
			entries: []string{"backups/2022/site/configuration.php", "backups/2022/site/includes/defines.php"},
			want:    true,
		},
		// An extension bundle that ships a configuration.php, next to an
		// unrelated tree holding a Joomla entry point, is not a site copy: the
		// configuration file and the runtime must belong to one directory.
		{
			name:    "extension-config-beside-other-tree.zip",
			entries: []string{"some-extension/configuration.php", "vendor-copy/includes/defines.php"},
			want:    false,
		},
		{
			name:    "extension-config-only.zip",
			entries: []string{"some-extension/configuration.php", "some-extension/some-extension.php"},
			want:    false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := filepath.Join(root, tc.name)
			writeZip(t, p, tc.entries...)
			if got := archiveHoldsSiteBackup(p); got != tc.want {
				t.Errorf("archiveHoldsSiteBackup(%s) = %v, want %v", tc.name, got, tc.want)
			}
		})
	}
}
