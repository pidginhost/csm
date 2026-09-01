package checks

import (
	"archive/zip"
	"os"
	"path/filepath"
	"testing"
)

// writeZip builds a zip at path whose entries are the given names. Contents are
// irrelevant: classification reads the entry list, not the payloads.
func writeZip(t *testing.T, path string, names ...string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create %s: %v", path, err)
	}
	defer f.Close()
	zw := zip.NewWriter(f)
	for _, n := range names {
		w, err := zw.Create(n)
		if err != nil {
			t.Fatalf("zip entry %s: %v", n, err)
		}
		if _, err := w.Write([]byte("x")); err != nil {
			t.Fatalf("write %s: %v", n, err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("close zip: %v", err)
	}
}

// A full-site backup whose name carries no backup token is still a site backup.
// scoalataspeciala.ro served www_scoalataspeciala.zip (64MB, containing
// wwwroot/wp-config.php) with no deny rule, because the name-only classifier
// returned classNone.
func TestArchiveContentIdentifiesUnnamedSiteBackup(t *testing.T) {
	root := t.TempDir()
	cases := []struct {
		name    string
		entries []string
		want    bool
	}{
		{
			name:    "www_example.zip",
			entries: []string{"wwwroot/index.php", "wwwroot/wp-config.php", "wwwroot/wp-load.php"},
			want:    true,
		},
		{
			name:    "site-2024.zip",
			entries: []string{"public_html/wp-config.php", "public_html/index.php"},
			want:    true,
		},
		// Isolates the CMS-config marker: no docroot directory name, so only
		// wp-config.php can carry this case.
		{
			name:    "snapshot-2024-01-01.zip",
			entries: []string{"snapshot-2024-01-01/index.php", "snapshot-2024-01-01/wp-config.php"},
			want:    true,
		},
		// Isolates the docroot-directory marker: a served tree with no CMS
		// config file in it at all.
		{
			name:    "htdocs-copy.zip",
			entries: []string{"htdocs/index.html", "htdocs/assets/style.css"},
			want:    true,
		},
		{
			name:    "export.zip",
			entries: []string{"database.sql", "uploads/logo.png"},
			want:    true,
		},
		// Benign long tail: ordinary downloads offered on purpose. These must
		// stay unclassified or the detector drowns operators in noise.
		{
			name:    "fullcalendar.zip",
			entries: []string{"fullcalendar/main.js", "fullcalendar/main.css"},
			want:    false,
		},
		{
			name:    "duplicator-pro.zip",
			entries: []string{"duplicator-pro/duplicator-pro.php", "duplicator-pro/readme.txt"},
			want:    false,
		},
		{
			name:    "brochure.zip",
			entries: []string{"brochure.pdf"},
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

// A plugin bundle that merely ships a .sql schema file is not a site backup.
// Requiring a site marker (wp-config.php, a docroot dir, or a dump at archive
// root) keeps installers out of the class.
func TestArchiveContentIgnoresPluginBundledSQL(t *testing.T) {
	root := t.TempDir()
	p := filepath.Join(root, "some-plugin.zip")
	writeZip(t, p, "some-plugin/some-plugin.php", "some-plugin/install/schema.sql")
	if archiveHoldsSiteBackup(p) {
		t.Error("plugin bundle with a nested schema.sql classified as a site backup")
	}
}

// Unreadable or non-zip input must not classify, and must not panic.
func TestArchiveContentHandlesUnreadable(t *testing.T) {
	root := t.TempDir()
	bad := filepath.Join(root, "truncated.zip")
	if err := os.WriteFile(bad, []byte("not a zip"), 0o644); err != nil {
		t.Fatal(err)
	}
	if archiveHoldsSiteBackup(bad) {
		t.Error("non-zip data classified as a site backup")
	}
	if archiveHoldsSiteBackup(filepath.Join(root, "missing.zip")) {
		t.Error("missing file classified as a site backup")
	}
}
