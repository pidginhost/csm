package mime

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/zipdir"
)

func gzipBytes(t *testing.T, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	if _, err := gw.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := gw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// rawTarMember lets tests construct metadata chains that tar.Writer folds
// into the following file instead of exposing as independent headers.
func rawTarMember(t testing.TB, kind byte, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	if err := tw.WriteHeader(&tar.Header{Name: "member", Size: int64(len(data)), Mode: 0o644, Format: tar.FormatGNU}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	raw := buf.Bytes()[:buf.Len()-1024]
	raw[156] = kind
	setTarChecksum(raw)
	return raw
}

func setTarChecksum(raw []byte) {
	copy(raw[148:156], "        ")
	sum := 0
	for _, b := range raw[:512] {
		sum += int(b)
	}
	copy(raw[148:156], fmt.Sprintf("%06o\x00 ", sum))
}

func extractArchiveFixture(t *testing.T, name string, data []byte, limits Limits) (*ExtractionResult, int64) {
	t.Helper()
	limits.TempDir = t.TempDir()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	result := &ExtractionResult{}
	var total int64
	if strings.HasSuffix(name, ".zip") {
		extractZIPPath(t, path, name, limits, result, &total, 1)
	} else {
		extractTarGzPath(t, path, name, limits, result, &total, 1)
	}
	t.Cleanup(func() {
		result.Close()
		requireTempDirEmpty(t, limits.TempDir)
	})
	return result, total
}

func TestZIPUnderreportedDirectoryIsRejectedBeforeExtraction(t *testing.T) {
	data := manyEntryZip(t, 65537)
	// Keep a classic end record whose count wraps, as archive/zip accepts.
	data = append(data[:len(data)-98], data[len(data)-22:]...)
	end := data[len(data)-22:]
	binary.LittleEndian.PutUint16(end[8:10], 1)
	binary.LittleEndian.PutUint16(end[10:12], 1)
	for _, shortSize := range []bool{false, true} {
		t.Run(fmt.Sprint(shortSize), func(t *testing.T) {
			archive := bytes.Clone(data)
			if shortSize {
				// Point the claimed directory at only the last entry while
				// retaining the earlier offset archive/zip tries as a fallback.
				binary.LittleEndian.PutUint32(archive[len(archive)-10:len(archive)-6], 46+uint32(len("e65536")))
			}
			limits := DefaultLimits()
			limits.MaxArchiveFiles = 1
			zr, err := zip.NewReader(bytes.NewReader(archive), int64(len(archive)))
			if err != nil || len(zr.File) != 65537 {
				t.Fatalf("underreported fixture is not readable: reader=%v err=%v", zr != nil, err)
			}
			r, _ := extractArchiveFixture(t, "count.zip", archive, limits)
			if !r.Partial || len(r.Parts) != 0 {
				t.Fatalf("underreported directory: partial=%v parts=%d reason=%q", r.Partial, len(r.Parts), r.PartialReason)
			}
		})
	}
}

func TestZIPPreflightStopsAtWalkCap(t *testing.T) {
	data := manyEntryZip(t, 100)
	end := data[len(data)-22:]
	binary.LittleEndian.PutUint16(end[8:10], 1)
	binary.LittleEndian.PutUint16(end[10:12], 1)
	dir, err := zipdir.Read(bytes.NewReader(data), int64(len(data)), maxZipDirectoryBytes)
	if err != nil {
		t.Fatal(err)
	}
	r := &zipListingReadCounter{ReaderAt: bytes.NewReader(data), start: dir.Offset, end: dir.Offset + dir.Size}
	if err := validateZIPDirectory(r, int64(len(data)), dir, 10); err != errArchiveWalk {
		t.Fatalf("preflight error = %v; want walk limit", err)
	}
	if r.headers != 10 {
		t.Fatalf("read %d directory headers; want 10", r.headers)
	}
}

type zipListingReadCounter struct {
	io.ReaderAt
	start, end int64
	headers    int
}

func (r *zipListingReadCounter) ReadAt(p []byte, off int64) (int, error) {
	if off >= r.start && off < r.end {
		r.headers++
	}
	return r.ReaderAt.ReadAt(p, off)
}

func TestZIP64CountAndAlternateEndAreRejected(t *testing.T) {
	zip64 := manyEntryZip(t, 65536)
	// A real ZIP64 listing must be refused even when its classic count wraps.
	comment := orderedZip(t, archiveEntry{"visible", []byte("body")})
	// A second end record inside the first one's comment is accepted by
	// archive/zip but not by zipdir.Read's exact comment-length check.
	fake := make([]byte, 23)
	binary.LittleEndian.PutUint32(fake[:4], zipdir.EndSignature)
	binary.LittleEndian.PutUint16(comment[len(comment)-2:], uint16(len(fake)))
	comment = append(comment, fake...)
	for name, data := range map[string][]byte{"zip64": zip64, "alternate-end": comment} {
		t.Run(name, func(t *testing.T) {
			r, _ := extractArchiveFixture(t, "ambiguous.zip", data, DefaultLimits())
			if !r.Partial || len(r.Parts) != 0 {
				t.Fatalf("partial=%v parts=%d reason=%q", r.Partial, len(r.Parts), r.PartialReason)
			}
		})
	}
}

func TestZIPPrefixAndCommentStayReadable(t *testing.T) {
	data := orderedZip(t, archiveEntry{"readable", []byte("body")})
	binary.LittleEndian.PutUint16(data[len(data)-2:], 7)
	data = append(data, []byte("comment")...)
	data = append([]byte("self-extracting prefix"), data...)
	r, _ := extractArchiveFixture(t, "prefixed.zip", data, DefaultLimits())
	if r.Partial || len(r.Parts) != 1 {
		t.Fatalf("partial=%v parts=%d reason=%q", r.Partial, len(r.Parts), r.PartialReason)
	}
	got, err := os.ReadFile(r.Parts[0].TempPath)
	if err != nil || string(got) != "body" {
		t.Fatalf("extracted body = %q, %v", got, err)
	}
}

func TestTarMetadataHeadersSpendWalkBudget(t *testing.T) {
	for _, kind := range []byte{tar.TypeXHeader, tar.TypeGNULongName, tar.TypeGNULongLink} {
		t.Run(fmt.Sprint(kind), func(t *testing.T) {
			payload := []byte("name\x00")
			if kind == tar.TypeXHeader {
				payload = []byte("13 comment=x\n")
			}
			raw := bytes.Repeat(rawTarMember(t, kind, payload), 11)
			raw = append(raw, rawTarMember(t, tar.TypeReg, []byte("tail"))...)
			raw = append(raw, make([]byte, 1024)...)
			limits := DefaultLimits()
			limits.MaxArchiveFiles = 1
			r, _ := extractArchiveFixture(t, "metadata.tgz", gzipBytes(t, raw), limits)
			if !r.Partial || !strings.Contains(r.PartialReason, "lists more than 10 entries") || len(r.Parts) != 0 {
				t.Fatalf("metadata walk: partial=%v parts=%d reason=%q", r.Partial, len(r.Parts), r.PartialReason)
			}
		})
	}
}

func TestTarEndDoesNotHideUnreadGzipContent(t *testing.T) {
	empty := make([]byte, 1024)
	badCRC := gzipBytes(t, empty)
	badCRC[len(badCRC)-8] ^= 1
	for name, data := range map[string][]byte{
		"checksum":           badCRC,
		"truncated":          gzipBytes(t, empty)[:len(gzipBytes(t, empty))-4],
		"second gzip stream": append(gzipBytes(t, empty), orderedTarGz(t, archiveEntry{"hidden", []byte("unread")})...),
		"trailing member":    gzipBytes(t, append(bytes.Clone(empty), rawTarMember(t, tar.TypeReg, []byte("unread"))...)),
	} {
		t.Run(name, func(t *testing.T) {
			r, _ := extractArchiveFixture(t, "trailer.tgz", data, DefaultLimits())
			if !r.Partial {
				t.Fatal("unread or corrupt trailing content reported complete")
			}
		})
	}
}

func TestTarFinalBlockCannotHideBudgetError(t *testing.T) {
	limits := DefaultLimits()
	limits.MaxExtractionSize = 1023
	r, total := extractArchiveFixture(t, "empty.tgz", gzipBytes(t, make([]byte, 1024)), limits)
	if !r.Partial || total != 1024 {
		t.Fatalf("partial=%v bytes=%d reason=%q", r.Partial, total, r.PartialReason)
	}
}

func TestArchiveByteBudgetStopsWithinOneProbeByte(t *testing.T) {
	for _, name := range []string{"large.zip", "large.tgz"} {
		t.Run(name, func(t *testing.T) {
			entries := []archiveEntry{{"large", make([]byte, 1<<20)}}
			data := orderedZip(t, entries...)
			if strings.HasSuffix(name, ".tgz") {
				data = orderedTarGz(t, entries...)
			}
			limits := DefaultLimits()
			// Above the member's compressed size (about 1 KiB), so inflating
			// is what crosses the budget and the probe byte is what stops it.
			limits.MaxExtractionSize = 4096
			r, total := extractArchiveFixture(t, name, data, limits)
			if !r.Partial || total != limits.MaxExtractionSize+1 || len(r.Parts) != 0 {
				t.Fatalf("partial=%v bytes=%d parts=%d", r.Partial, total, len(r.Parts))
			}
		})
	}
}

func TestEmptyAndDirectoryOnlyArchivesStayComplete(t *testing.T) {
	var dirs bytes.Buffer
	tw := tar.NewWriter(&dirs)
	for i := 0; i < 10; i++ {
		if err := tw.WriteHeader(&tar.Header{Name: fmt.Sprintf("d%d/", i), Typeflag: tar.TypeDir}); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string][]byte{
		"empty.zip":       manyEntryZip(t, 0),
		"empty.tgz":       gzipBytes(t, make([]byte, 1024)),
		"directories.tgz": gzipBytes(t, dirs.Bytes()),
		"padded.tgz":      gzipBytes(t, append(dirs.Bytes(), make([]byte, 8192)...)),
	} {
		t.Run(name, func(t *testing.T) {
			limits := DefaultLimits()
			limits.MaxArchiveFiles = 1
			r, _ := extractArchiveFixture(t, name, data, limits)
			if r.Partial || len(r.Parts) != 0 {
				t.Fatalf("valid empty archive: partial=%v parts=%d reason=%q", r.Partial, len(r.Parts), r.PartialReason)
			}
		})
	}
}

func TestBudgetReaderBoundsUnderlyingRead(t *testing.T) {
	var spent int64
	b := &budgetReader{r: strings.NewReader(strings.Repeat("x", 8192)), spent: &spent, limit: 10}
	n, err := io.Copy(io.Discard, b)
	if err != errExtractionBudget || n != 11 || spent != 11 {
		t.Fatalf("Read: n=%d counted=%d err=%v; want 11 bytes and budget error", n, spent, err)
	}
}

func TestArchiveSkippedDataIsPartial(t *testing.T) {
	var zb bytes.Buffer
	zw := zip.NewWriter(&zb)
	w, err := zw.Create("data")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("hidden")); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	zipData := bytes.ReplaceAll(zb.Bytes(), []byte("data"), []byte("dir/"))
	for name, data := range map[string][]byte{
		"directory.zip": zipData,
		"unknown.tgz":   gzipBytes(t, append(rawTarMember(t, 'Z', []byte("hidden")), make([]byte, 1024)...)),
	} {
		t.Run(name, func(t *testing.T) {
			r, _ := extractArchiveFixture(t, name, data, DefaultLimits())
			if !r.Partial {
				t.Fatal("skipped member data reported complete")
			}
		})
	}
}

func TestDeflatedEmptyZIPDirectoryStaysComplete(t *testing.T) {
	data := bytes.ReplaceAll(orderedZip(t, archiveEntry{"data", nil}), []byte("data"), []byte("dir/"))
	r, _ := extractArchiveFixture(t, "directory.zip", data, DefaultLimits())
	if r.Partial || len(r.Parts) != 0 {
		t.Fatalf("empty deflated directory: partial=%v parts=%d reason=%q", r.Partial, len(r.Parts), r.PartialReason)
	}
}

func TestZIPDirectoryCannotHideDataBehindRepeatedSlashes(t *testing.T) {
	data := bytes.ReplaceAll(orderedZip(t, archiveEntry{"data", []byte("hidden")}), []byte("data"), []byte("di//"))
	header := bytes.Index(data, []byte("PK\x01\x02"))
	if header < 0 {
		t.Fatal("missing central header")
	}
	binary.LittleEndian.PutUint32(data[header+24:header+28], 0)
	r, _ := extractArchiveFixture(t, "directory.zip", data, DefaultLimits())
	if !r.Partial || len(r.Parts) != 0 {
		t.Fatalf("directory payload: partial=%v parts=%d reason=%q", r.Partial, len(r.Parts), r.PartialReason)
	}
}

func TestTarDirectorySizeIsNotPayload(t *testing.T) {
	raw := rawTarMember(t, tar.TypeDir, nil)
	copy(raw[124:136], "00000001000\x00")
	setTarChecksum(raw)
	raw = append(raw, make([]byte, 1024)...)
	r, _ := extractArchiveFixture(t, "directory.tgz", gzipBytes(t, raw), DefaultLimits())
	if r.Partial || len(r.Parts) != 0 {
		t.Fatalf("header-only directory: partial=%v parts=%d reason=%q", r.Partial, len(r.Parts), r.PartialReason)
	}
}

func TestArchiveWalkCapCannotWrap(t *testing.T) {
	limits := DefaultLimits()
	limits.MaxArchiveFiles = int(^uint(0) >> 1)
	if got := archiveWalkCap(limits); got != limits.MaxArchiveFiles {
		t.Fatalf("walk cap = %d; want saturated max int", got)
	}
}

func TestTarSplitAcrossGzipStreamsStaysComplete(t *testing.T) {
	raw := append(rawTarMember(t, tar.TypeReg, []byte("body")), make([]byte, 1024)...)
	data := append(gzipBytes(t, raw[:600]), gzipBytes(t, raw[600:])...)
	r, _ := extractArchiveFixture(t, "split.tgz", data, DefaultLimits())
	if r.Partial || len(r.Parts) != 1 {
		t.Fatalf("split gzip: partial=%v parts=%d reason=%q", r.Partial, len(r.Parts), r.PartialReason)
	}
	got, err := os.ReadFile(r.Parts[0].TempPath)
	if err != nil || string(got) != "body" {
		t.Fatalf("extracted body = %q, %v", got, err)
	}
}

func TestEmptyGzipStreamsCannotLoopPastWalkCap(t *testing.T) {
	data := bytes.Repeat(gzipBytes(t, nil), 11)
	data = append(data, orderedTarGz(t, archiveEntry{"unread", []byte("body")})...)
	limits := DefaultLimits()
	limits.MaxArchiveFiles = 1
	r, _ := extractArchiveFixture(t, "streams.tgz", data, limits)
	if !r.Partial || !strings.Contains(r.PartialReason, "lists more than 10 entries") || len(r.Parts) != 0 {
		t.Fatalf("empty stream walk: partial=%v parts=%d reason=%q", r.Partial, len(r.Parts), r.PartialReason)
	}
}

func TestTarMetadataPreservesReadableMembers(t *testing.T) {
	for _, kind := range []byte{tar.TypeXHeader, tar.TypeXGlobalHeader, tar.TypeGNULongName, tar.TypeGNULongLink} {
		t.Run(fmt.Sprint(kind), func(t *testing.T) {
			metadata := []byte("name\x00")
			if kind == tar.TypeXHeader || kind == tar.TypeXGlobalHeader {
				metadata = []byte("13 comment=x\n")
			}
			raw := rawTarMember(t, kind, metadata)
			raw = append(raw, rawTarMember(t, tar.TypeReg, bytes.Repeat([]byte("b"), 600))...)
			raw = append(raw, make([]byte, 1024)...)
			r, _ := extractArchiveFixture(t, "metadata.tgz", gzipBytes(t, raw), DefaultLimits())
			if r.Partial || len(r.Parts) != 1 || r.Parts[0].Size != 600 {
				t.Fatalf("metadata: partial=%v parts=%+v reason=%q", r.Partial, r.Parts, r.PartialReason)
			}
			got, err := os.ReadFile(r.Parts[0].TempPath)
			if err != nil || !bytes.Equal(got, bytes.Repeat([]byte("b"), 600)) {
				t.Fatalf("metadata member changed: length=%d err=%v", len(got), err)
			}
		})
	}
}

func TestTarPAXSizeControlsPayloadFraming(t *testing.T) {
	member := rawTarMember(t, tar.TypeReg, bytes.Repeat([]byte("b"), 600))
	copy(member[124:136], "00000000000\x00")
	setTarChecksum(member)
	raw := append(rawTarMember(t, tar.TypeXHeader, []byte("12 size=600\n")), member...)
	raw = append(raw, rawTarMember(t, tar.TypeReg, []byte("tail"))...)
	raw = append(raw, make([]byte, 1024)...)
	r, _ := extractArchiveFixture(t, "pax.tgz", gzipBytes(t, raw), DefaultLimits())
	if r.Partial || len(r.Parts) != 2 || r.Parts[0].Size != 600 || r.Parts[1].Size != 4 {
		t.Fatalf("PAX sizes: partial=%v parts=%+v reason=%q", r.Partial, r.Parts, r.PartialReason)
	}
}

func TestSparseTarMembersCannotBypassByteBudget(t *testing.T) {
	oldGNU := rawTarMember(t, tar.TypeGNUSparse, nil)
	copy(oldGNU[483:495], "00004000000\x00") // logical size, no stored extent data
	setTarChecksum(oldGNU)
	// A zero-length extent describes a hole-only file to archive/tar.
	pax := rawTarMember(t, tar.TypeXHeader, []byte("26 GNU.sparse.numblocks=1\n22 GNU.sparse.map=0,0\n27 GNU.sparse.size=1048576\n"))
	pax = append(pax, rawTarMember(t, tar.TypeReg, nil)...)
	for name, raw := range map[string][]byte{"gnu": oldGNU, "pax": pax} {
		t.Run(name, func(t *testing.T) {
			raw = append(raw, make([]byte, 1024)...)
			tr := tar.NewReader(bytes.NewReader(raw))
			hdr, err := tr.Next()
			if err != nil || hdr.Size != 1<<20 {
				t.Fatalf("invalid sparse fixture: header=%+v err=%v", hdr, err)
			}
			limits := DefaultLimits()
			limits.MaxExtractionSize = 8192
			r, total := extractArchiveFixture(t, "sparse.tgz", gzipBytes(t, raw), limits)
			if !r.Partial || len(r.Parts) != 0 || total > limits.MaxExtractionSize+1 {
				t.Fatalf("sparse content: partial=%v parts=%d bytes=%d", r.Partial, len(r.Parts), total)
			}
			if name == "pax" {
				limits.MaxExtractionSize = 2 << 20
				complete, expanded := extractArchiveFixture(t, "readable.tgz", gzipBytes(t, raw), limits)
				if complete.Partial || len(complete.Parts) != 1 || expanded != int64(len(raw))+(1<<20) {
					t.Fatalf("readable sparse content: partial=%v parts=%d bytes=%d reason=%q", complete.Partial, len(complete.Parts), expanded, complete.PartialReason)
				}
				got, readErr := os.ReadFile(complete.Parts[0].TempPath)
				if readErr != nil || !bytes.Equal(got, make([]byte, 1<<20)) {
					t.Fatalf("sparse contents: len=%d err=%v", len(got), readErr)
				}
			}
		})
	}
}

func TestEncryptedZIPDirectoryUsesEncryptedPolicy(t *testing.T) {
	data := bytes.ReplaceAll(orderedZip(t, archiveEntry{"data", nil}), []byte("data"), []byte("dir/"))
	data = patchZipEntries(t, data, true, 99, 1)
	r, _ := extractArchiveFixture(t, "encrypted.zip", data, DefaultLimits())
	if r.Partial || len(r.EncryptedEntries) != 1 || len(r.Parts) != 0 {
		t.Fatalf("encrypted directory: partial=%v encrypted=%d parts=%d reason=%q", r.Partial, len(r.EncryptedEntries), len(r.Parts), r.PartialReason)
	}
}

func TestPAXSparseMapPreservesPhysicalFraming(t *testing.T) {
	for _, sizeRecord := range []string{"", "8 size=\n"} {
		t.Run(fmt.Sprintf("size_record_%t", sizeRecord != ""), func(t *testing.T) {
			metadata := []byte("22 GNU.sparse.major=1\n22 GNU.sparse.minor=0\n26 GNU.sparse.realsize=32\n" + sizeRecord)
			stored := make([]byte, 512)
			copy(stored, "1\n10\n4\n")
			stored = append(stored, []byte("data")...)
			raw := append(rawTarMember(t, tar.TypeXHeader, metadata), rawTarMember(t, tar.TypeReg, stored)...)
			raw = append(raw, rawTarMember(t, tar.TypeReg, []byte("tail"))...)
			raw = append(raw, make([]byte, 1024)...)
			r, total := extractArchiveFixture(t, "sparse-map.tgz", gzipBytes(t, raw), DefaultLimits())
			if r.Partial || len(r.Parts) != 2 || total != int64(len(raw))+28 {
				t.Fatalf("sparse framing: partial=%v parts=%d bytes=%d reason=%q", r.Partial, len(r.Parts), total, r.PartialReason)
			}
			want := make([]byte, 32)
			copy(want[10:], "data")
			for i, expected := range [][]byte{want, []byte("tail")} {
				got, err := os.ReadFile(r.Parts[i].TempPath)
				if err != nil || !bytes.Equal(got, expected) {
					t.Fatalf("part %d: got %q err=%v", i, got, err)
				}
			}
		})
	}
}
