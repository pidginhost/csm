package mime

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/binary"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/zipdir"
)

func TestZipInZipAtDefaultDepthIsPartial(t *testing.T) {
	inner := buildZipArchive(t, map[string][]byte{"evil.txt": []byte("payload")})
	outer := buildZipArchive(t, map[string][]byte{"inner.zip": inner})
	body := buildMultipartBody("BOUND", "outer.zip", "application/zip", outer)
	r := parseWithLimits(t, `multipart/mixed; boundary="BOUND"`, body, DefaultLimits()) // depth 1
	if !r.Partial || !strings.Contains(r.PartialReason, `nested archive "inner.zip" not expanded`) {
		t.Fatalf("Partial=%v reason=%q", r.Partial, r.PartialReason)
	}
	for _, p := range r.Parts {
		if p.Filename == "evil.txt" {
			t.Fatal("expanded past max_archive_depth")
		}
	}
}

func TestZipInZipWithinDepthIsExpanded(t *testing.T) {
	limits := DefaultLimits()
	limits.MaxArchiveDepth = 2
	limits.TempDir = t.TempDir()
	inner := buildTarGzArchive(t, map[string][]byte{"../../evil\n.txt": []byte("payload")})
	outer := buildZipArchive(t, map[string][]byte{"dir/inner.tar.gz": inner})
	body := buildMultipartBody("BOUND", "outer.zip", "application/zip", outer)
	r := parseWithLimits(t, `multipart/mixed; boundary="BOUND"`, body, limits)
	if r.Partial {
		t.Fatalf("partial within depth: %q", r.PartialReason)
	}
	var found bool
	for _, p := range r.Parts {
		if p.Filename == "evil" && p.Nested && p.ArchiveName == "inner.tar.gz" {
			found = true // name sanitised: base name, cut at the control character
		}
	}
	if !found {
		t.Fatalf("inner member missing or unsanitised: %+v", r.Parts)
	}
	for _, p := range r.Parts {
		_ = os.Remove(p.TempPath)
	}
	requireTempDirEmpty(t, limits.TempDir)
}

func TestDepthLimitStopsDeeperArchives(t *testing.T) {
	limits := DefaultLimits()
	limits.MaxArchiveDepth = 2
	l3 := buildZipArchive(t, map[string][]byte{"deep.txt": []byte("x")})
	l2 := buildZipArchive(t, map[string][]byte{"l3.zip": l3})
	l1 := buildZipArchive(t, map[string][]byte{"l2.zip": l2})
	body := buildMultipartBody("BOUND", "l1.zip", "application/zip", l1)
	r := parseWithLimits(t, `multipart/mixed; boundary="BOUND"`, body, limits)
	if !r.Partial || !strings.Contains(r.PartialReason, `nested archive "l3.zip" not expanded`) {
		t.Fatalf("Partial=%v reason=%q", r.Partial, r.PartialReason)
	}
}

func TestSinglePartZipMessageIsExpanded(t *testing.T) {
	zipBytes := buildZipArchive(t, map[string][]byte{"x.txt": []byte("inside")})
	body := base64.StdEncoding.EncodeToString(zipBytes)
	r := parseEncodedSpool(t, `application/zip; name="a.zip"`, "base64", body)
	var found bool
	for _, p := range r.Parts {
		found = found || (p.Filename == "x.txt" && p.Nested)
	}
	if !found {
		t.Fatalf("single-part zip not expanded: %+v", r.Parts)
	}
}

// A single-part body named only by Content-Disposition is unpacked like a
// multipart attachment named the same way.
func TestSinglePartZipNamedByDispositionIsExpanded(t *testing.T) {
	zipBytes := buildZipArchive(t, map[string][]byte{"x.txt": []byte("inside")})
	h, d := buildEximSpool(t, "application/octet-stream", base64.StdEncoding.EncodeToString(zipBytes))
	header, err := os.ReadFile(h)
	if err != nil {
		t.Fatal(err)
	}
	header = append(header, eximHdr(' ', "Content-Transfer-Encoding: base64")...)
	header = append(header, eximHdr(' ', `Content-Disposition: attachment; filename="x.zip"`)...)
	if err = os.WriteFile(h, header, 0o600); err != nil {
		t.Fatal(err)
	}
	limits := DefaultLimits()
	limits.TempDir = t.TempDir()
	r, err := ParseSpoolMessage(h, d, limits)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, p := range r.Parts {
		found = found || (p.Filename == "x.txt" && p.Nested)
	}
	if !found {
		t.Fatalf("single-part zip named by Content-Disposition not expanded: %+v", r.Parts)
	}
}

// Exhausting the budget inside an inner ZIP must also stop its outer siblings.
func TestNestedZipStopsAtSharedBudget(t *testing.T) {
	inner := orderedZip(t, archiveEntry{"large.bin", make([]byte, 128<<10)})
	outer := orderedZip(t,
		archiveEntry{"inner.zip", inner},
		archiveEntry{"sibling.bin", make([]byte, 128<<10)},
	)
	limits := DefaultLimits()
	limits.MaxArchiveDepth = 2
	limits.MaxExtractionSize = int64(len(inner)) + 1024
	limits.TempDir = t.TempDir()
	path := filepath.Join(t.TempDir(), "outer.zip")
	if err := os.WriteFile(path, outer, 0o600); err != nil {
		t.Fatal(err)
	}
	var result ExtractionResult
	var spent int64
	extractZIP(path, "outer.zip", limits, &result, &spent, 1)
	for _, part := range result.Parts {
		if err := os.Remove(part.TempPath); err != nil {
			t.Fatal(err)
		}
	}
	requireTempDirEmpty(t, limits.TempDir)
	if !result.Partial || !strings.Contains(result.PartialReason, "total extraction size") {
		t.Fatalf("exhausted budget not reported: %+v", result)
	}
	if len(result.Parts) != 1 || result.Parts[0].Filename != "inner.zip" {
		t.Fatalf("unexpected parts after budget exhaustion: %+v", result.Parts)
	}
	if spent != limits.MaxExtractionSize+1 {
		t.Fatalf("decompressed %d bytes, want at most one probe byte past %d", spent, limits.MaxExtractionSize)
	}
}

func TestNestedTarEndMarkersSpendSharedBudget(t *testing.T) {
	inner := orderedTarGz(t, archiveEntry{"leaf.txt", []byte("x")})
	outer := orderedZip(t, archiveEntry{"inner.tar.gz", inner})
	// A zip member costs the larger of its compressed and inflated sizes;
	// gzip data does not deflate, so its stored size may be the larger. The
	// TAR then holds a header, one padded data block, and two end blocks.
	zr, err := zip.NewReader(bytes.NewReader(outer), int64(len(outer)))
	if err != nil {
		t.Fatal(err)
	}
	wantSpent := max(int64(zr.File[0].CompressedSize64), int64(len(inner))) + 4*512
	for _, tc := range []struct {
		name    string
		limit   int64
		partial bool
	}{
		{"exact", wantSpent, false},
		{"one byte short", wantSpent - 1, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			limits := DefaultLimits()
			limits.MaxArchiveDepth = 2
			limits.MaxExtractionSize = tc.limit
			limits.TempDir = t.TempDir()
			path := filepath.Join(t.TempDir(), "outer.zip")
			if err := os.WriteFile(path, outer, 0o600); err != nil {
				t.Fatal(err)
			}
			var result ExtractionResult
			var spent int64
			extractZIP(path, "outer.zip", limits, &result, &spent, 1)
			for _, part := range result.Parts {
				if err := os.Remove(part.TempPath); err != nil {
					t.Fatal(err)
				}
			}
			requireTempDirEmpty(t, limits.TempDir)
			if spent != wantSpent || result.Partial != tc.partial {
				t.Fatalf("spent=%d Partial=%v reason=%q; want spent=%d Partial=%v", spent, result.Partial, result.PartialReason, wantSpent, tc.partial)
			}
			if len(result.Parts) != 2 || result.Parts[1].Filename != "leaf.txt" {
				t.Fatalf("readable members lost: %+v", result.Parts)
			}
		})
	}
}

func TestNestedZipUnreadDirectoryTailIsPartial(t *testing.T) {
	inner := orderedZip(t, archiveEntry{"leaf.txt", []byte("hello")})
	end := append([]byte(nil), inner[len(inner)-zipdir.EndLen:]...)
	binary.LittleEndian.PutUint32(end[12:16], binary.LittleEndian.Uint32(end[12:16])+4)
	inner = append(inner[:len(inner)-zipdir.EndLen], []byte("junk")...)
	inner = append(inner, end...)
	outer := orderedZip(t, archiveEntry{"inner.zip", inner})
	limits := DefaultLimits()
	limits.MaxArchiveDepth = 2
	limits.TempDir = t.TempDir()
	body := buildMultipartBody("BOUND", "outer.zip", "application/zip", outer)
	r := parseWithLimits(t, `multipart/mixed; boundary="BOUND"`, body, limits)
	for _, part := range r.Parts {
		if err := os.Remove(part.TempPath); err != nil {
			t.Fatal(err)
		}
	}
	requireTempDirEmpty(t, limits.TempDir)
	if !r.Partial || !strings.Contains(r.PartialReason, `archive "inner.zip" could not be opened`) {
		t.Fatalf("unread nested directory reported clean: Partial=%v reason=%q", r.Partial, r.PartialReason)
	}
}

func TestNestedTarGzValidatesStreamAfterTarEnd(t *testing.T) {
	valid := orderedTarGz(t, archiveEntry{"leaf.txt", []byte("hello")})
	badChecksum := append([]byte(nil), valid...)
	badChecksum[len(badChecksum)-8] ^= 1
	concatenated := append(append([]byte(nil), valid...), valid...)
	// TAR writers may add zero padding after their two end blocks.
	gr, err := gzip.NewReader(bytes.NewReader(valid))
	if err != nil {
		t.Fatal(err)
	}
	rawTar, err := io.ReadAll(gr)
	if err != nil {
		t.Fatal(err)
	}
	if err := gr.Close(); err != nil {
		t.Fatal(err)
	}
	var padded bytes.Buffer
	gw := gzip.NewWriter(&padded)
	if _, err := gw.Write(append(rawTar, make([]byte, 4096)...)); err != nil {
		t.Fatal(err)
	}
	if err := gw.Close(); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name          string
		archive       []byte
		partial       bool
		paddingBudget bool
	}{
		{name: "valid", archive: valid},
		{name: "zero padding", archive: padded.Bytes()},
		{name: "bad checksum", archive: badChecksum, partial: true},
		{name: "truncated trailer", archive: valid[:len(valid)-4], partial: true},
		{name: "unread second archive", archive: concatenated, partial: true},
		{name: "padding exceeds budget", archive: padded.Bytes(), partial: true, paddingBudget: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			outer := orderedZip(t, archiveEntry{"inner.tar.gz", tc.archive})
			limits := DefaultLimits()
			limits.MaxArchiveDepth = 2
			if tc.paddingBudget {
				limits.MaxExtractionSize = int64(len(outer) + len(tc.archive) + len(rawTar) + 64)
			}
			limits.TempDir = t.TempDir()
			body := buildMultipartBody("BOUND", "outer.zip", "application/zip", outer)
			r := parseWithLimits(t, `multipart/mixed; boundary="BOUND"`, body, limits)
			for _, part := range r.Parts {
				if err := os.Remove(part.TempPath); err != nil {
					t.Fatal(err)
				}
			}
			requireTempDirEmpty(t, limits.TempDir)
			if r.Partial != tc.partial {
				t.Fatalf("Partial=%v reason=%q, want Partial=%v", r.Partial, r.PartialReason, tc.partial)
			}
			if tc.paddingBudget && !strings.Contains(r.PartialReason, "total extraction size") {
				t.Fatalf("padding did not spend the shared budget: %q", r.PartialReason)
			}
			if len(r.Parts) != 3 || r.Parts[2].Filename != "leaf.txt" {
				t.Fatalf("readable members lost: %+v", r.Parts)
			}
		})
	}
}

// Mail clients show a part named only by its Content-Type name parameter
// under that name, so the parser must unpack it the same way.
func TestMultipartZipNamedByContentTypeIsExpanded(t *testing.T) {
	zipBytes := buildZipArchive(t, map[string][]byte{"x.txt": []byte("inside")})
	body := "--BOUND\r\n" +
		"Content-Type: application/zip; name=\"evil.zip\"\r\n" +
		"Content-Transfer-Encoding: base64\r\n" +
		"Content-Disposition: attachment\r\n\r\n" +
		base64.StdEncoding.EncodeToString(zipBytes) + "\r\n" +
		"--BOUND--\r\n"
	r := parseWithLimits(t, `multipart/mixed; boundary="BOUND"`, body, DefaultLimits())
	var outer, inner bool
	for _, p := range r.Parts {
		outer = outer || (p.Filename == "evil.zip" && !p.Nested)
		inner = inner || (p.Filename == "x.txt" && p.Nested && p.ArchiveName == "evil.zip")
	}
	if !outer || !inner {
		t.Fatalf("part named by Content-Type not expanded: %+v", r.Parts)
	}
}
