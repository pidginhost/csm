package mime

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
)

// manyEntryZip lists n empty stored entries.
func manyEntryZip(t *testing.T, n int) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for i := 0; i < n; i++ {
		if _, err := zw.CreateHeader(&zip.FileHeader{Name: fmt.Sprintf("e%d", i), Method: zip.Store}); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// symlinkTarGz holds n symlink headers, then one regular file.
func symlinkTarGz(t *testing.T, n int, last string, lastBody []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)
	for i := 0; i < n; i++ {
		if err := tw.WriteHeader(&tar.Header{Name: fmt.Sprintf("l%d", i), Typeflag: tar.TypeSymlink, Linkname: "target"}); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.WriteHeader(&tar.Header{Name: last, Size: int64(len(lastBody)), Mode: 0o644}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(lastBody); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// requireTempDirEmpty fails when the parser left a staged file behind that
// is not listed in a result (the caller removes listed parts first).
func requireTempDirEmpty(t *testing.T, dir string) {
	t.Helper()
	left, err := filepath.Glob(filepath.Join(dir, "csm-emailav-*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(left) != 0 {
		t.Fatalf("temp files left behind: %v", left)
	}
}

func TestZipListingPastWalkCapIsPartial(t *testing.T) {
	limits := DefaultLimits() // MaxArchiveFiles 50 -> walk cap 500
	limits.TempDir = t.TempDir()
	body := buildMultipartBody("BOUND", "huge.zip", "application/zip", manyEntryZip(t, 50000))
	r := parseWithLimits(t, `multipart/mixed; boundary="BOUND"`, body, limits)
	if !r.Partial || !strings.Contains(r.PartialReason, `archive "huge.zip" lists more than 500 entries`) {
		t.Fatalf("Partial=%v reason=%q", r.Partial, r.PartialReason)
	}
	for _, p := range r.Parts {
		if p.Nested {
			t.Fatalf("members extracted from an over-cap listing: %+v", p)
		}
	}
}

func TestTarHeadersCountTowardWalkCap(t *testing.T) {
	limits := DefaultLimits()
	archive := symlinkTarGz(t, 600, "last.txt", []byte("tail"))
	body := buildMultipartBody("BOUND", "links.tar.gz", "application/gzip", archive)
	r := parseWithLimits(t, `multipart/mixed; boundary="BOUND"`, body, limits)
	if !r.Partial || !strings.Contains(r.PartialReason, "lists more than 500 entries") {
		t.Fatalf("Partial=%v reason=%q", r.Partial, r.PartialReason)
	}
	for _, p := range r.Parts {
		if p.Filename == "last.txt" {
			t.Fatal("extraction continued past the walk cap")
		}
	}
}

func TestDiscardedZipMembersSpendTheBudget(t *testing.T) {
	limits := DefaultLimits()
	limits.MaxAttachmentSize = 2 << 20
	limits.MaxExtractionSize = 10 << 20
	limits.TempDir = t.TempDir()
	var entries []archiveEntry
	for i := 0; i < 8; i++ {
		entries = append(entries, archiveEntry{fmt.Sprintf("big%d.bin", i), make([]byte, 3<<20)}) // each over the per-member cap
	}
	entries = append(entries, archiveEntry{"zz-last.txt", []byte("kept only if the budget were ignored")})
	body := buildMultipartBody("BOUND", "bomb.zip", "application/zip", orderedZip(t, entries...))
	r := parseWithLimits(t, `multipart/mixed; boundary="BOUND"`, body, limits)
	if !r.Partial {
		t.Fatal("bomb not partial")
	}
	for _, p := range r.Parts {
		if p.Filename == "zz-last.txt" {
			t.Fatal("extraction went on after the decompressed budget was spent")
		}
	}
	r.Close()
	requireTempDirEmpty(t, limits.TempDir)
}

func TestTarSkippedRemainderSpendsTheBudget(t *testing.T) {
	limits := DefaultLimits()
	limits.MaxAttachmentSize = 1 << 20
	limits.MaxExtractionSize = 4 << 20
	archive := orderedTarGz(t,
		archiveEntry{"a-big.bin", make([]byte, 8<<20)},
		archiveEntry{"z-last.txt", []byte("after the skip")},
	)
	body := buildMultipartBody("BOUND", "skip.tar.gz", "application/gzip", archive)
	r := parseWithLimits(t, `multipart/mixed; boundary="BOUND"`, body, limits)
	if !r.Partial {
		t.Fatal("not partial")
	}
	for _, p := range r.Parts {
		if p.Filename == "z-last.txt" {
			t.Fatal("the bytes skipped past an oversize member were not counted")
		}
	}
}

// Directories and encrypted members do not count toward max_archive_files:
// ordinary archives must not start failing because of them.
func TestDirectoriesAndEncryptedEntriesDoNotCountAsExtracted(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for i := 0; i < 60; i++ {
		if _, err := zw.Create(fmt.Sprintf("d%d/", i)); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 3; i++ {
		w, err := zw.Create(fmt.Sprintf("f%d.txt", i))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte("body")); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	dirs := parseZipAttachment(t, buf.Bytes())
	nested := 0
	for _, p := range dirs.Parts {
		if p.Nested {
			nested++
		}
	}
	if dirs.Partial || nested != 3 {
		t.Fatalf("directories: Partial=%v reason=%q nested=%d", dirs.Partial, dirs.PartialReason, nested)
	}

	files := map[string][]byte{}
	for i := 0; i < 60; i++ {
		files[fmt.Sprintf("secret%02d.pdf", i)] = []byte("%PDF-1.4 body")
	}
	encrypted := patchZipEntries(t, buildZipArchive(t, files), true, 0xffff, 60)
	enc := parseZipAttachment(t, encrypted)
	if enc.Partial || len(enc.EncryptedEntries) != 50 || enc.EncryptedEntriesOmitted != 10 {
		t.Fatalf("encrypted: Partial=%v reason=%q names=%d omitted=%d",
			enc.Partial, enc.PartialReason, len(enc.EncryptedEntries), enc.EncryptedEntriesOmitted)
	}
}
