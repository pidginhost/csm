package mime

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"os"
	"strings"
	"testing"
)

// parseWithLimits parses a synthetic spool message and removes every staged
// part when the test ends.
func parseWithLimits(t *testing.T, contentType, body string, limits Limits) *ExtractionResult {
	t.Helper()
	hPath, dPath := buildEximSpool(t, contentType, body)
	result, err := ParseSpoolMessage(hPath, dPath, limits)
	if err != nil {
		t.Fatalf("ParseSpoolMessage: %v", err)
	}
	t.Cleanup(func() {
		for _, p := range result.Parts {
			_ = os.Remove(p.TempPath)
		}
	})
	return result
}

// archiveEntry is one archive member. The ordered builders write members in
// the order given; buildZipArchive and buildTarGzArchive range over a map.
type archiveEntry struct {
	name string
	data []byte
}

func orderedZip(t *testing.T, entries ...archiveEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, e := range entries {
		w, err := zw.Create(e.name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(e.data); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func orderedTarGz(t *testing.T, entries ...archiveEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)
	for _, e := range entries {
		if err := tw.WriteHeader(&tar.Header{Name: e.name, Size: int64(len(e.data)), Mode: 0o644}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(e.data); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestCorruptZipAttachmentIsPartial(t *testing.T) {
	bad := []byte("PK\x03\x04 not a zip archive, only padding to look like one ............")
	body := buildMultipartBody("BOUND", "bad.zip", "application/zip", bad)
	r := parseWithLimits(t, `multipart/mixed; boundary="BOUND"`, body, DefaultLimits())
	if !r.Partial || !strings.Contains(r.PartialReason, `archive "bad.zip" could not be opened`) {
		t.Fatalf("Partial=%v reason=%q", r.Partial, r.PartialReason)
	}
	if len(r.Parts) != 1 || r.Parts[0].Filename != "bad.zip" {
		t.Fatalf("the raw archive must still be scanned: %+v", r.Parts)
	}
}

func TestCorruptGzipAttachmentIsPartial(t *testing.T) {
	body := buildMultipartBody("BOUND", "bad.tar.gz", "application/gzip", []byte("not gzip at all"))
	r := parseWithLimits(t, `multipart/mixed; boundary="BOUND"`, body, DefaultLimits())
	if !r.Partial || !strings.Contains(r.PartialReason, `archive "bad.tar.gz" could not be opened`) {
		t.Fatalf("Partial=%v reason=%q", r.Partial, r.PartialReason)
	}
}

// A tar stream that breaks at a member header, not inside member data: the
// first member reads cleanly and the next header is cut short.
func TestTruncatedTarGzIsPartial(t *testing.T) {
	var raw bytes.Buffer
	tw := tar.NewWriter(&raw)
	for _, name := range []string{"a.txt", "b.txt"} {
		data := bytes.Repeat([]byte(name[:1]), 64<<10)
		if err := tw.WriteHeader(&tar.Header{Name: name, Size: int64(len(data)), Mode: 0o644}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	cut := raw.Bytes()[:512+64<<10+200] // first member whole, 200 bytes of the second header
	var gz bytes.Buffer
	gw := gzip.NewWriter(&gz)
	if _, err := gw.Write(cut); err != nil {
		t.Fatal(err)
	}
	if err := gw.Close(); err != nil {
		t.Fatal(err)
	}
	body := buildMultipartBody("BOUND", "cut.tar.gz", "application/gzip", gz.Bytes())
	r := parseWithLimits(t, `multipart/mixed; boundary="BOUND"`, body, DefaultLimits())
	if !r.Partial || !strings.Contains(r.PartialReason, `archive "cut.tar.gz" could not be read`) {
		t.Fatalf("Partial=%v reason=%q", r.Partial, r.PartialReason)
	}
	var first bool
	for _, p := range r.Parts {
		first = first || (p.Filename == "a.txt" && p.Nested)
	}
	if !first {
		t.Fatalf("the readable first member must still be extracted: %+v", r.Parts)
	}
}

func TestValidArchivesStayComplete(t *testing.T) {
	files := map[string][]byte{"doc.txt": []byte("hello"), "empty.txt": {}, "dir/x.bin": {1, 2}}
	for name, archive := range map[string][]byte{
		"ok.zip":    buildZipArchive(t, files),
		"ok.tar.gz": buildTarGzArchive(t, files),
	} {
		body := buildMultipartBody("BOUND", name, "application/octet-stream", archive)
		r := parseWithLimits(t, `multipart/mixed; boundary="BOUND"`, body, DefaultLimits())
		if r.Partial {
			t.Errorf("%s: valid archive marked partial: %q", name, r.PartialReason)
		}
	}
}
