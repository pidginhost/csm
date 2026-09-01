package checks

import (
	"archive/zip"
	"context"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// writeZip builds a zip at path whose entries are the given names. Contents are
// irrelevant: classification reads the entry list, not the payloads.
func writeZip(t *testing.T, path string, names ...string) {
	writeZipWithComment(t, path, "", names...)
}

func writeZipWithComment(t *testing.T, path, comment string, names ...string) {
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
	if err := zw.SetComment(comment); err != nil {
		t.Fatalf("zip comment: %v", err)
	}
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

// A full WordPress tree can contain thousands of files before wp-config.php in
// central-directory order. Classification must not depend on the marker being
// among an arbitrary first batch of entries.
func TestArchiveContentScansPastFormerEntryLimit(t *testing.T) {
	const formerEntryLimit = 4096
	names := make([]string, 0, formerEntryLimit+1)
	for i := 0; i < formerEntryLimit; i++ {
		names = append(names, fmt.Sprintf("mysite-2024-01-01/wp-content/cache/%04d.dat", i))
	}
	names = append(names, "mysite-2024-01-01/wp-config.php")

	p := filepath.Join(t.TempDir(), "mysite-2024-01-01.zip")
	writeZip(t, p, names...)
	if !archiveHoldsSiteBackup(p) {
		t.Error("site marker after the former entry cutoff was not classified")
	}
}

// An entry comment can contain bytes that look like a second end record. Only
// an end record whose declared comment reaches EOF can terminate the archive;
// otherwise a crafted comment can hide the real central directory.
func TestArchiveContentIgnoresFalseDirectoryEndInsideComment(t *testing.T) {
	comment := make([]byte, zipDirectoryEndLen+1)
	binary.LittleEndian.PutUint32(comment[0:4], zipDirectoryEndSignature)
	comment[len(comment)-1] = 'x'
	p := filepath.Join(t.TempDir(), "site.zip")
	writeZipWithComment(t, p, string(comment), "wp-config.php")
	if !archiveHoldsSiteBackup(p) {
		t.Error("false end record inside the archive comment hid the site marker")
	}
}

// Generic configuration filenames inside extension bundles are not evidence
// that the archive contains a live site.
func TestArchiveContentIgnoresGenericNestedConfigurationFiles(t *testing.T) {
	root := t.TempDir()
	for _, entry := range []string{
		"some-plugin/settings.php",
		"some-plugin/configuration.php",
		"some-plugin/config/database.php",
	} {
		p := filepath.Join(root, filepath.Base(entry)+".zip")
		writeZip(t, p, entry)
		if archiveHoldsSiteBackup(p) {
			t.Errorf("generic nested config %q classified as a site backup", entry)
		}
	}
}

func TestArchiveContentRecognizesStructuredCMSConfigurationPaths(t *testing.T) {
	root := t.TempDir()
	for _, entry := range []string{"site/sites/default/settings.php"} {
		p := filepath.Join(root, filepath.Base(entry)+".zip")
		writeZip(t, p, entry)
		if !archiveHoldsSiteBackup(p) {
			t.Errorf("structured site config %q was not classified", entry)
		}
	}
}

// Entry names that would escape an extraction root do not prove the archive
// contains a site. The scanner never extracts them, but it must not normalize
// traversal into a trusted-looking marker either.
func TestArchiveContentIgnoresTraversalNames(t *testing.T) {
	p := filepath.Join(t.TempDir(), "traversal.zip")
	writeZip(t, p, "../wp-config.php", "/public_html/index.php", `..\wp-config.php`, `C:\public_html\index.php`)
	if archiveHoldsSiteBackup(p) {
		t.Error("insecure archive entry name classified as a site backup")
	}
}

// Account users can replace a candidate between the directory walk and the
// content check. A FIFO or symlink must not strand the scheduled scan.
func TestArchiveContentDoesNotBlockOnFIFO(t *testing.T) {
	p := filepath.Join(t.TempDir(), "account.zip")
	if err := syscall.Mkfifo(p, 0o600); err != nil {
		t.Fatalf("mkfifo: %v", err)
	}

	done := make(chan bool, 1)
	go func() { done <- archiveHoldsSiteBackup(p) }()
	select {
	case got := <-done:
		if got {
			t.Error("FIFO classified as a site backup")
		}
	case <-time.After(time.Second):
		t.Fatal("archive content check blocked opening an account-controlled FIFO")
	}
}

// A neutral archive name can be a symlink that the vhost serves. Following a
// regular-file target is required for the content classifier; O_NONBLOCK and
// the descriptor type check still reject a special-file swap safely.
func TestArchiveContentFollowsRegularSymlink(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "stored", "site.zip")
	writeZip(t, target, "public_html/index.php")
	link := filepath.Join(root, "download.zip")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	if !archiveHoldsSiteBackup(link) {
		t.Error("regular zip reached through a web-served symlink was not classified")
	}
}

func TestArchiveContentBoundsCentralDirectoryBytes(t *testing.T) {
	// The end record alone is enough to prove the declared central directory
	// exceeds the limit. Inspection must stop before allocating entry metadata.
	raw := make([]byte, zipDirectoryEndLen)
	binary.LittleEndian.PutUint32(raw[0:4], zipDirectoryEndSignature)
	binary.LittleEndian.PutUint16(raw[8:10], 1)
	binary.LittleEndian.PutUint16(raw[10:12], 1)
	binary.LittleEndian.PutUint32(raw[12:16], archiveDirectoryScanByteLimit+1)
	p := filepath.Join(t.TempDir(), "oversized-directory.zip")
	if err := os.WriteFile(p, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	holds, complete := archiveSiteBackupStatus(context.Background(), p)
	if holds || complete {
		t.Fatalf("oversized central directory status = (%v, %v), want (false, false)", holds, complete)
	}
}

func TestArchiveContentLimitMarksExposureScanIncomplete(t *testing.T) {
	root := t.TempDir()
	raw := make([]byte, zipDirectoryEndLen)
	binary.LittleEndian.PutUint32(raw[0:4], zipDirectoryEndSignature)
	binary.LittleEndian.PutUint16(raw[8:10], 1)
	binary.LittleEndian.PutUint16(raw[10:12], 1)
	binary.LittleEndian.PutUint32(raw[12:16], archiveDirectoryScanByteLimit+1)
	if err := os.WriteFile(filepath.Join(root, "site.zip"), raw, 0o600); err != nil {
		t.Fatal(err)
	}

	ctx, incomplete := withIncompleteCheckCollector(context.Background())
	findings := scanVhostsForExposure(ctx, []vhost{{
		domain: "example.com", docroot: root, ip: "192.0.2.10",
	}}, nil)
	if len(findings) != 0 {
		t.Fatalf("resource-limited archive produced findings: %+v", findings)
	}
	if !incomplete.contains("exposed_files") {
		t.Fatal("resource-limited archive did not preserve exposure scan state")
	}
}

func TestArchiveContentReadsZip64Directory(t *testing.T) {
	name := []byte("wp-config.php")
	directory := make([]byte, zipDirectoryHeaderLen+len(name))
	binary.LittleEndian.PutUint32(directory[0:4], zipDirectoryHeaderSignature)
	binary.LittleEndian.PutUint16(directory[28:30], uint16(len(name)))
	copy(directory[zipDirectoryHeaderLen:], name)

	zip64End := make([]byte, zipDirectory64EndLen)
	binary.LittleEndian.PutUint32(zip64End[0:4], zipDirectory64EndSignature)
	binary.LittleEndian.PutUint64(zip64End[4:12], zipDirectory64EndLen-12)
	binary.LittleEndian.PutUint64(zip64End[24:32], 1)
	binary.LittleEndian.PutUint64(zip64End[32:40], 1)
	binary.LittleEndian.PutUint64(zip64End[40:48], uint64(len(directory)))

	locator := make([]byte, zipDirectory64LocLen)
	binary.LittleEndian.PutUint32(locator[0:4], zipDirectory64LocSignature)
	binary.LittleEndian.PutUint64(locator[8:16], uint64(len(directory)))
	binary.LittleEndian.PutUint32(locator[16:20], 1)

	end := make([]byte, zipDirectoryEndLen)
	binary.LittleEndian.PutUint32(end[0:4], zipDirectoryEndSignature)
	binary.LittleEndian.PutUint16(end[8:10], 0xffff)
	binary.LittleEndian.PutUint16(end[10:12], 0xffff)
	binary.LittleEndian.PutUint32(end[12:16], 0xffffffff)
	binary.LittleEndian.PutUint32(end[16:20], 0xffffffff)

	p := filepath.Join(t.TempDir(), "site.zip")
	raw := make([]byte, 0, len(directory)+len(zip64End)+len(locator)+len(end))
	raw = append(raw, directory...)
	raw = append(raw, zip64End...)
	raw = append(raw, locator...)
	raw = append(raw, end...)
	if err := os.WriteFile(p, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if !archiveHoldsSiteBackup(p) {
		t.Error("ZIP64 central directory was not classified")
	}
}

type cancelOnSecondErrContext struct {
	context.Context
	calls int
}

func (c *cancelOnSecondErrContext) Err() error {
	c.calls++
	if c.calls >= 2 {
		return context.Canceled
	}
	return nil
}

// Once a valid site marker has been read, cancellation makes the inspection
// incomplete but must not erase the evidence already found.
func TestArchiveContentRetainsMarkerFoundBeforeCancellation(t *testing.T) {
	names := make([]string, 257)
	names[0] = "wp-config.php"
	for i := 1; i < len(names); i++ {
		names[i] = fmt.Sprintf("assets/%03d.dat", i)
	}
	p := filepath.Join(t.TempDir(), "site.zip")
	writeZip(t, p, names...)

	ctx := &cancelOnSecondErrContext{Context: context.Background()}
	holds, complete := archiveSiteBackupStatus(ctx, p)
	if !holds || complete {
		t.Fatalf("cancelled archive status = (%v, %v), want (true, false)", holds, complete)
	}
}

func TestArchiveOffsetRejectsOverflow(t *testing.T) {
	got, ok := archiveOffset(1<<63 - 1)
	if !ok || got != 1<<63-1 {
		t.Fatalf("max int64 offset: got (%d, %v)", got, ok)
	}
	if _, ok := archiveOffset(1 << 63); ok {
		t.Error("offset above max int64 was accepted")
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
