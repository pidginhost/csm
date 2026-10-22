package mime

import (
	"archive/zip"
	"bytes"
	"compress/flate"
	"encoding/binary"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/zipdir"
)

// emptyDeflate returns a deflate stream of n bytes or more that inflates to
// nothing: a run of empty sync-flush blocks.
func emptyDeflate(t *testing.T, n int) []byte {
	t.Helper()
	var buf bytes.Buffer
	w, err := flate.NewWriter(&buf, flate.NoCompression)
	if err != nil {
		t.Fatal(err)
	}
	for buf.Len() < n {
		if err := w.Flush(); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// sharedOffsetZip lists records central-directory records that all point at
// one stored local entry whose data is raw, the way a hostile writer can.
func sharedOffsetZip(t *testing.T, name string, raw []byte, records int) []byte {
	t.Helper()
	// zip.Writer refuses data under a directory name, so write a same-length
	// placeholder and put the real name into both headers afterwards.
	placeholder := strings.Repeat("x", len(name))
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.CreateRaw(&zip.FileHeader{Name: placeholder, Method: zip.Deflate, CompressedSize64: uint64(len(raw))})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = w.Write(raw); err != nil {
		t.Fatal(err)
	}
	if err = zw.Close(); err != nil {
		t.Fatal(err)
	}
	one := buf.Bytes()
	copy(one[30:], name) // local header name
	dir, err := zipdir.Read(bytes.NewReader(one), int64(len(one)), 16<<20)
	if err != nil {
		t.Fatal(err)
	}
	record := one[dir.Offset : dir.Offset+dir.Size]
	copy(record[zipdir.HeaderLen:], name) // central directory name
	end := append([]byte(nil), one[dir.Offset+dir.Size:]...)
	binary.LittleEndian.PutUint16(end[8:10], uint16(records))
	binary.LittleEndian.PutUint16(end[10:12], uint16(records))
	binary.LittleEndian.PutUint32(end[12:16], uint32(len(record)*records))
	out := append([]byte(nil), one[:dir.Offset]...)
	out = append(out, bytes.Repeat(record, records)...)
	return append(out, end...)
}

// A directory entry may not carry a large compressed stream: inflating it to
// prove it empty would cost CPU without ever spending the byte budget.
func TestZipDirectoryWithLargeStreamIsPartialWithoutInflating(t *testing.T) {
	data := sharedOffsetZip(t, "d/", emptyDeflate(t, 100<<10), 400)
	r, total := extractArchiveFixture(t, "dirs.zip", data, DefaultLimits())
	if !r.Partial || !strings.Contains(r.PartialReason, "contains unread data") {
		t.Fatalf("Partial=%v reason=%q", r.Partial, r.PartialReason)
	}
	if total != 0 {
		t.Fatalf("budget spent on a directory: %d", total)
	}
}

// Records sharing one compressed stream each spend its compressed size, so a
// stream that inflates to nothing cannot be re-inflated for free.
func TestSharedCompressedStreamSpendsTheBudget(t *testing.T) {
	limits := DefaultLimits()
	limits.MaxArchiveFiles = 1000
	limits.MaxExtractionSize = 20 << 20
	data := sharedOffsetZip(t, "f.txt", emptyDeflate(t, 1<<20), 200)
	r, total := extractArchiveFixture(t, "shared.zip", data, limits)
	if !r.Partial || !strings.Contains(r.PartialReason, "total extraction size exceeds") {
		t.Fatalf("Partial=%v reason=%q total=%d parts=%d", r.Partial, r.PartialReason, total, len(r.Parts))
	}
	if len(r.Parts) > 21 {
		t.Fatalf("inflated %d records sharing one stream before stopping", len(r.Parts))
	}
}
