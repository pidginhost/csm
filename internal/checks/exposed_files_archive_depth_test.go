package checks

import (
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
