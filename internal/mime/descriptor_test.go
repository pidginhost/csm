package mime

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"
)

type attachment struct {
	name string
	data []byte
}

// multipartSpool writes a spool pair whose body carries the attachments in
// order, base64-encoded.
func multipartSpool(t *testing.T, atts ...attachment) (hPath, dPath string) {
	t.Helper()
	const boundary = "csm-test-boundary"
	var b strings.Builder
	b.WriteString("--" + boundary + "\r\nContent-Type: text/plain\r\n\r\nhello\r\n")
	for _, a := range atts {
		fmt.Fprintf(&b, "--%s\r\nContent-Type: application/octet-stream; name=%q\r\nContent-Disposition: attachment; filename=%q\r\nContent-Transfer-Encoding: base64\r\n\r\n%s\r\n",
			boundary, a.name, a.name, base64.StdEncoding.EncodeToString(a.data))
	}
	b.WriteString("--" + boundary + "--\r\n")
	return buildEximSpool(t, "multipart/mixed; boundary="+boundary, b.String())
}

func openPair(t *testing.T, hPath, dPath string) (*os.File, *os.File) {
	t.Helper()
	h, err := os.Open(hPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = h.Close() })
	d, err := os.Open(dPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	return h, d
}

func partBytes(t *testing.T, p ExtractedPart) []byte {
	t.Helper()
	b, err := io.ReadAll(io.NewSectionReader(p.File, 0, p.Size))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func descriptorFixtures(t *testing.T) map[string][2]string {
	t.Helper()
	out := map[string][2]string{}
	h, d := multipartSpool(t, attachment{"invoice.pdf", []byte("%PDF-1.4 test")})
	out["plain"] = [2]string{h, d}
	h, d = multipartSpool(t, attachment{"files.zip", buildZipArchive(t, map[string][]byte{"a.txt": []byte("alpha"), "b.txt": []byte("beta")})})
	out["zip"] = [2]string{h, d}
	h, d = multipartSpool(t, attachment{"files.tar.gz", buildTarGzArchive(t, map[string][]byte{"c.txt": []byte("gamma")})})
	out["tgz"] = [2]string{h, d}
	return out
}

func TestParseSpoolFilesMatchesPathParse(t *testing.T) {
	for name, pair := range descriptorFixtures(t) {
		t.Run(name, func(t *testing.T) {
			byPath, err := ParseSpoolMessage(pair[0], pair[1], DefaultLimits())
			if err != nil {
				t.Fatal(err)
			}
			defer byPath.Close()
			h, d := openPair(t, pair[0], pair[1])
			byFile, err := ParseSpoolFiles(h, d, DefaultLimits())
			if err != nil {
				t.Fatal(err)
			}
			defer byFile.Close()
			if len(byFile.Parts) != len(byPath.Parts) || len(byFile.Parts) == 0 || byFile.Partial != byPath.Partial {
				t.Fatalf("parts %d vs %d, partial %v vs %v", len(byFile.Parts), len(byPath.Parts), byFile.Partial, byPath.Partial)
			}
			names := map[string][]byte{}
			for _, p := range byPath.Parts {
				onDisk, err := os.ReadFile(p.TempPath)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(onDisk, partBytes(t, p)) {
					t.Fatalf("%s: File and TempPath differ", p.Filename)
				}
				names[p.Filename] = onDisk
			}
			for _, p := range byFile.Parts {
				if want, ok := names[p.Filename]; !ok || !bytes.Equal(want, partBytes(t, p)) || int64(len(want)) != p.Size {
					t.Fatalf("part %q differs from the path parse", p.Filename)
				}
			}
		})
	}
}

func TestParseSpoolFilesUsesPartSink(t *testing.T) {
	pair := descriptorFixtures(t)["zip"]
	h, d := openPair(t, pair[0], pair[1])
	dir := t.TempDir()
	calls := 0
	limits := DefaultLimits()
	limits.PartSink = func(prefix string) (*os.File, error) {
		calls++
		return os.CreateTemp(dir, prefix)
	}
	res, err := ParseSpoolFiles(h, d, limits)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Close()
	if calls != len(res.Parts) || calls != 3 {
		t.Fatalf("sink called %d times for %d parts", calls, len(res.Parts))
	}
	for _, p := range res.Parts {
		if p.TempPath != "" || p.File == nil {
			t.Fatalf("part %q: TempPath %q File %v", p.Filename, p.TempPath, p.File)
		}
	}
}

func TestParseSpoolFilesIgnoresSharedOffset(t *testing.T) {
	pair := descriptorFixtures(t)["plain"]
	h, d := openPair(t, pair[0], pair[1])
	dOffset, err := d.Seek(0, io.SeekEnd)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = h.Seek(7, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	res, err := ParseSpoolFiles(h, d, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	defer res.Close()
	if len(res.Parts) != 1 || res.Parts[0].Filename != "invoice.pdf" || string(partBytes(t, res.Parts[0])) != "%PDF-1.4 test" {
		t.Fatalf("parts = %+v", res.Parts)
	}
	for f, want := range map[*os.File]int64{h: 7, d: dOffset} {
		if got, err := f.Seek(0, io.SeekCurrent); err != nil || got != want {
			t.Fatalf("input offset = %d, %v; want %d", got, err, want)
		}
	}
}

func TestArchiveMembersReadFromStagedFile(t *testing.T) {
	pair := descriptorFixtures(t)["zip"]
	h, d := openPair(t, pair[0], pair[1])
	dir := t.TempDir()
	limits := DefaultLimits()
	limits.PartSink = func(prefix string) (*os.File, error) {
		f, err := os.CreateTemp(dir, prefix)
		if err == nil {
			err = os.Remove(f.Name()) // nothing can reopen it by name
		}
		return f, err
	}
	res, err := ParseSpoolFiles(h, d, limits)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Close()
	got := map[string]string{}
	for _, p := range res.Parts {
		if p.Nested {
			got[p.Filename] = string(partBytes(t, p))
		}
	}
	if got["a.txt"] != "alpha" || got["b.txt"] != "beta" || res.Partial {
		t.Fatalf("members = %v partial %v (%s)", got, res.Partial, res.PartialReason)
	}
}

func TestParseSpoolFilesCapsParts(t *testing.T) {
	var atts []attachment
	for i := range 5 {
		atts = append(atts, attachment{fmt.Sprintf("f%d.bin", i), []byte{byte(i + 1)}})
	}
	hPath, dPath := multipartSpool(t, atts...)
	h, d := openPair(t, hPath, dPath)
	limits := DefaultLimits()
	limits.MaxParts = 3
	res, err := ParseSpoolFiles(h, d, limits)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Close()
	if len(res.Parts) != 3 || !res.Partial || res.PartialReason != "message has more than 3 attachments" {
		t.Fatalf("parts %d partial %v reason %q", len(res.Parts), res.Partial, res.PartialReason)
	}
}

func TestSanitizeAttachmentNameCapsOnRuneBoundary(t *testing.T) {
	got := SanitizeAttachmentName(strings.Repeat("é", 200))
	if len(got) != 254 || !utf8.ValidString(got) {
		t.Fatalf("len %d valid %v", len(got), utf8.ValidString(got))
	}
	if got := TruncateUTF8("abc", 10); got != "abc" {
		t.Fatalf("short string changed: %q", got)
	}
	if got := TruncateUTF8("aé", 2); got != "a" {
		t.Fatalf("split rune kept: %q", got)
	}
}

func TestExtractionResultCloseRemovesTempFiles(t *testing.T) {
	pair := descriptorFixtures(t)["zip"]
	dir := t.TempDir()
	limits := DefaultLimits()
	limits.TempDir = dir
	res, err := ParseSpoolMessage(pair[0], pair[1], limits)
	if err != nil {
		t.Fatal(err)
	}
	res.Close()
	left, _ := filepath.Glob(filepath.Join(dir, "*"))
	if len(left) != 0 {
		t.Fatalf("Close left %v", left)
	}
}

// openArchive opens a fixture archive for extractZIP and extractTarGz, which
// read from a staged part's open file.
func openArchive(t *testing.T, path string) (*os.File, int64) {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	st, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	return f, st.Size()
}

func extractZIPPath(t *testing.T, path, name string, limits Limits, result *ExtractionResult, total *int64, depth int) {
	t.Helper()
	f, size := openArchive(t, path)
	extractZIP(f, size, name, limits, result, total, depth)
}

func extractTarGzPath(t *testing.T, path, name string, limits Limits, result *ExtractionResult, total *int64, depth int) {
	t.Helper()
	f, size := openArchive(t, path)
	extractTarGz(f, size, name, limits, result, total, depth)
}

func readBodyFileLimited(t *testing.T, path string, limit int64) ([]byte, bool, error) {
	t.Helper()
	f, _ := openArchive(t, path)
	return readBodyLimited(f, limit)
}

// Every staged part holds an open file, so the default limits must cap them.
func TestDefaultLimitsCapParts(t *testing.T) {
	if got := DefaultLimits().MaxParts; got != MaxParts || MaxParts != 200 {
		t.Fatalf("DefaultLimits().MaxParts = %d, MaxParts = %d; want 200", got, MaxParts)
	}
}
