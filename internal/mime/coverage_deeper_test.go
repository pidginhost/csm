package mime

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// --- extractMultipart: nested multipart (multipart/alternative inside multipart/mixed) ---

func TestExtractMultipartNestedMultipart(t *testing.T) {
	innerBoundary := "INNER"
	innerBody := "--" + innerBoundary + "\r\n" +
		"Content-Type: text/plain\r\n\r\n" +
		"Plain text.\r\n" +
		"--" + innerBoundary + "\r\n" +
		"Content-Type: text/html\r\n\r\n" +
		"<p>HTML text.</p>\r\n" +
		"--" + innerBoundary + "--\r\n"

	outerBoundary := "OUTER"
	outerBody := "--" + outerBoundary + "\r\n" +
		"Content-Type: multipart/alternative; boundary=\"" + innerBoundary + "\"\r\n\r\n" +
		innerBody +
		"--" + outerBoundary + "\r\n" +
		"Content-Type: application/octet-stream; name=\"malware.bin\"\r\n" +
		"Content-Transfer-Encoding: base64\r\n" +
		"Content-Disposition: attachment; filename=\"malware.bin\"\r\n\r\n" +
		base64.StdEncoding.EncodeToString([]byte("evil bytes")) + "\r\n" +
		"--" + outerBoundary + "--\r\n"

	hPath, dPath := buildEximSpool(t, `multipart/mixed; boundary="OUTER"`, outerBody)
	result, err := ParseSpoolMessage(hPath, dPath, DefaultLimits())
	if err != nil {
		t.Fatalf("ParseSpoolMessage: %v", err)
	}
	defer func() {
		for _, p := range result.Parts {
			os.Remove(p.TempPath)
		}
	}()

	if len(result.Parts) != 1 {
		t.Fatalf("Parts = %d, want 1 (nested text parts should be skipped)", len(result.Parts))
	}
	if result.Parts[0].Filename != "malware.bin" {
		t.Errorf("Filename = %q, want malware.bin", result.Parts[0].Filename)
	}
}

// A crafted email can nest multipart wrappers arbitrarily deep; recursion
// must stop at a sane cap and mark the extraction partial instead of
// recursing once per wrapper. The attachment hidden below the cap is then
// handled by the partial-extraction policy (tempfail/fail-open), not
// silently delivered as "no attachments".
func TestExtractMultipartCapsMimeNestingDepth(t *testing.T) {
	const depth = 64
	part := "Content-Type: application/octet-stream\r\n" +
		"Content-Disposition: attachment; filename=\"payload.bin\"\r\n\r\n" +
		"DATA\r\n"
	for i := depth - 1; i >= 1; i-- {
		bnd := fmt.Sprintf("nest%03d", i)
		part = "Content-Type: multipart/mixed; boundary=\"" + bnd + "\"\r\n\r\n" +
			"--" + bnd + "\r\n" + part + "--" + bnd + "--\r\n"
	}
	outer := "nest000"
	body := "--" + outer + "\r\n" + part + "--" + outer + "--\r\n"

	hPath, dPath := buildEximSpool(t, `multipart/mixed; boundary="nest000"`, body)
	result, err := ParseSpoolMessage(hPath, dPath, DefaultLimits())
	if err != nil {
		t.Fatalf("ParseSpoolMessage: %v", err)
	}
	defer func() {
		for _, p := range result.Parts {
			os.Remove(p.TempPath)
		}
	}()

	if !result.Partial {
		t.Fatal("64-deep MIME nesting must mark the extraction partial")
	}
}

// Legitimate mail commonly nests mixed > alternative > related; a shallow
// nest must extract normally and not be marked partial.
func TestExtractMultipartAllowsTypicalNesting(t *testing.T) {
	inner := "Content-Type: application/octet-stream\r\n" +
		"Content-Disposition: attachment; filename=\"report.bin\"\r\n\r\n" +
		"DATA\r\n"
	part := inner
	for i := 3; i >= 1; i-- {
		bnd := fmt.Sprintf("lvl%03d", i)
		part = "Content-Type: multipart/mixed; boundary=\"" + bnd + "\"\r\n\r\n" +
			"--" + bnd + "\r\n" + part + "--" + bnd + "--\r\n"
	}
	outer := "lvl000"
	body := "--" + outer + "\r\n" + part + "--" + outer + "--\r\n"

	hPath, dPath := buildEximSpool(t, `multipart/mixed; boundary="lvl000"`, body)
	result, err := ParseSpoolMessage(hPath, dPath, DefaultLimits())
	if err != nil {
		t.Fatalf("ParseSpoolMessage: %v", err)
	}
	defer func() {
		for _, p := range result.Parts {
			os.Remove(p.TempPath)
		}
	}()

	if result.Partial {
		t.Fatalf("typical 4-level nesting must not be partial: %s", result.PartialReason)
	}
	if len(result.Parts) != 1 || result.Parts[0].Filename != "report.bin" {
		t.Fatalf("Parts = %+v, want the nested attachment", result.Parts)
	}
}

// --- extractMultipart: unnamed non-text attachment -----------------------

func TestExtractMultipartUnnamedNonTextAttachment(t *testing.T) {
	boundary := "BOUND"
	payload := []byte{0x89, 0x50, 0x4E, 0x47} // PNG magic bytes
	encoded := base64.StdEncoding.EncodeToString(payload)

	body := "--" + boundary + "\r\n" +
		"Content-Type: text/plain\r\n\r\n" +
		"Hello.\r\n" +
		"--" + boundary + "\r\n" +
		"Content-Type: image/png\r\n" +
		"Content-Transfer-Encoding: base64\r\n\r\n" +
		encoded + "\r\n" +
		"--" + boundary + "--\r\n"

	hPath, dPath := buildEximSpool(t, `multipart/mixed; boundary="BOUND"`, body)
	result, err := ParseSpoolMessage(hPath, dPath, DefaultLimits())
	if err != nil {
		t.Fatalf("ParseSpoolMessage: %v", err)
	}
	defer func() {
		for _, p := range result.Parts {
			os.Remove(p.TempPath)
		}
	}()

	if len(result.Parts) != 1 {
		t.Fatalf("Parts = %d, want 1 (unnamed non-text should still be extracted)", len(result.Parts))
	}
	if result.Parts[0].Filename != "unnamed_attachment" {
		t.Errorf("Filename = %q, want unnamed_attachment", result.Parts[0].Filename)
	}
}

// --- extractMultipart: quoted-printable attachment -----------------------

func TestExtractMultipartQuotedPrintableAttachment(t *testing.T) {
	boundary := "BOUND"
	body := "--" + boundary + "\r\n" +
		"Content-Type: text/plain\r\n\r\n" +
		"Body.\r\n" +
		"--" + boundary + "\r\n" +
		"Content-Type: application/octet-stream; name=\"doc.bin\"\r\n" +
		"Content-Transfer-Encoding: quoted-printable\r\n" +
		"Content-Disposition: attachment; filename=\"doc.bin\"\r\n\r\n" +
		"Hello=20World\r\n" +
		"--" + boundary + "--\r\n"

	hPath, dPath := buildEximSpool(t, `multipart/mixed; boundary="BOUND"`, body)
	result, err := ParseSpoolMessage(hPath, dPath, DefaultLimits())
	if err != nil {
		t.Fatalf("ParseSpoolMessage: %v", err)
	}
	defer func() {
		for _, p := range result.Parts {
			os.Remove(p.TempPath)
		}
	}()

	found := false
	for _, p := range result.Parts {
		if p.Filename == "doc.bin" {
			found = true
			data, err := os.ReadFile(p.TempPath)
			if err != nil {
				t.Fatal(err)
			}
			if string(data) != "Hello World" {
				t.Errorf("decoded content = %q, want 'Hello World'", data)
			}
		}
	}
	if !found {
		t.Error("doc.bin attachment not found in parts")
	}
}

// --- extractMultipart: totalSize exceeded during multipart extraction ----

func TestExtractMultipartTotalSizeExceeded(t *testing.T) {
	// Build an attachment large enough to blow the total size budget.
	bigPayload := make([]byte, 200)
	for i := range bigPayload {
		bigPayload[i] = 'X'
	}

	boundary := "BOUND"
	body := buildMultipartBody(boundary, "big1.bin", "application/octet-stream", bigPayload)
	// Append a second attachment by adding another part before the closing delimiter.
	body = strings.Replace(body, "--"+boundary+"--", "", 1)
	body += "--" + boundary + "\r\n" +
		"Content-Type: application/octet-stream; name=\"big2.bin\"\r\n" +
		"Content-Transfer-Encoding: base64\r\n" +
		"Content-Disposition: attachment; filename=\"big2.bin\"\r\n\r\n" +
		base64.StdEncoding.EncodeToString(bigPayload) + "\r\n" +
		"--" + boundary + "--\r\n"

	hPath, dPath := buildEximSpool(t, `multipart/mixed; boundary="BOUND"`, body)

	limits := DefaultLimits()
	limits.MaxExtractionSize = 250 // smaller than 2x200
	result, err := ParseSpoolMessage(hPath, dPath, limits)
	if err != nil {
		t.Fatalf("ParseSpoolMessage: %v", err)
	}
	defer func() {
		for _, p := range result.Parts {
			os.Remove(p.TempPath)
		}
	}()

	if !result.Partial {
		t.Error("Partial should be true when total extraction size exceeded")
	}
	if !strings.Contains(result.PartialReason, "total extraction size") {
		t.Errorf("PartialReason = %q, want 'total extraction size...'", result.PartialReason)
	}
}

// --- extractMultipart: attachment exceeds max size -----------------------

func TestExtractMultipartAttachmentExceedsMaxSize(t *testing.T) {
	bigPayload := make([]byte, 500)
	for i := range bigPayload {
		bigPayload[i] = 'A'
	}

	body := buildMultipartBody("BOUND", "huge.bin", "application/octet-stream", bigPayload)
	hPath, dPath := buildEximSpool(t, `multipart/mixed; boundary="BOUND"`, body)

	limits := DefaultLimits()
	limits.MaxAttachmentSize = 100 // smaller than 500
	result, err := ParseSpoolMessage(hPath, dPath, limits)
	if err != nil {
		t.Fatalf("ParseSpoolMessage: %v", err)
	}
	defer func() {
		for _, p := range result.Parts {
			os.Remove(p.TempPath)
		}
	}()

	if !result.Partial {
		t.Error("Partial should be true when attachment exceeds max size")
	}
	// The oversized attachment should have been discarded.
	for _, p := range result.Parts {
		if p.Filename == "huge.bin" {
			t.Error("oversized attachment should not be in Parts")
		}
	}
}

// --- extractMultipart: .tgz extension is also recognized ----------------

func TestExtractTgzExtension(t *testing.T) {
	archive := buildTarGzArchive(t, map[string][]byte{
		"inner.txt": []byte("tgz contents"),
	})
	body := buildMultipartBody("BOUND", "payload.tgz", "application/gzip", archive)
	hPath, dPath := buildEximSpool(t, `multipart/mixed; boundary="BOUND"`, body)

	result, err := ParseSpoolMessage(hPath, dPath, DefaultLimits())
	if err != nil {
		t.Fatalf("ParseSpoolMessage: %v", err)
	}
	defer func() {
		for _, p := range result.Parts {
			os.Remove(p.TempPath)
		}
	}()

	hasInner := false
	for _, p := range result.Parts {
		if p.Filename == "inner.txt" && p.Nested && p.ArchiveName == "payload.tgz" {
			hasInner = true
		}
	}
	if !hasInner {
		t.Errorf("inner.txt from .tgz should be extracted; parts=%+v", result.Parts)
	}
}

// --- extractZIP: file inside archive exceeds max size -------------------

func TestExtractZIPInnerFileExceedsMaxSize(t *testing.T) {
	bigFile := make([]byte, 500)
	for i := range bigFile {
		bigFile[i] = 'Z'
	}
	archive := buildZipArchive(t, map[string][]byte{
		"small.txt": []byte("ok"),
		"huge.bin":  bigFile,
	})
	body := buildMultipartBody("BOUND", "payload.zip", "application/zip", archive)
	hPath, dPath := buildEximSpool(t, `multipart/mixed; boundary="BOUND"`, body)

	limits := DefaultLimits()
	limits.MaxAttachmentSize = 100
	result, err := ParseSpoolMessage(hPath, dPath, limits)
	if err != nil {
		t.Fatalf("ParseSpoolMessage: %v", err)
	}
	defer func() {
		for _, p := range result.Parts {
			os.Remove(p.TempPath)
		}
	}()

	if !result.Partial {
		t.Error("Partial should be true when zip inner file exceeds max")
	}
	// small.txt may or may not be extracted depending on zip iteration order,
	// but huge.bin should definitely not be present as a nested part.
	for _, p := range result.Parts {
		if p.Filename == "huge.bin" && p.Nested {
			t.Error("oversized inner file should not be extracted from zip")
		}
	}
}

func TestExtractTarGzInnerFileExceedsMaxSizeSetsPartial(t *testing.T) {
	bigFile := make([]byte, 500)
	for i := range bigFile {
		bigFile[i] = 'T'
	}
	archive := buildTarGzArchive(t, map[string][]byte{
		"huge.bin": bigFile,
	})
	body := buildMultipartBody("BOUND", "payload.tar.gz", "application/gzip", archive)
	hPath, dPath := buildEximSpool(t, `multipart/mixed; boundary="BOUND"`, body)

	limits := DefaultLimits()
	limits.MaxAttachmentSize = 100
	result, err := ParseSpoolMessage(hPath, dPath, limits)
	if err != nil {
		t.Fatalf("ParseSpoolMessage: %v", err)
	}
	defer func() {
		for _, p := range result.Parts {
			_ = os.Remove(p.TempPath)
		}
	}()

	if !result.Partial {
		t.Error("Partial should be true when tar.gz inner file exceeds max")
	}
	if !strings.Contains(result.PartialReason, "huge.bin") {
		t.Errorf("PartialReason = %q, want sanitized inner file name", result.PartialReason)
	}
	for _, p := range result.Parts {
		if p.Filename == "huge.bin" && p.Nested {
			t.Error("oversized inner file should not be extracted from tar.gz")
		}
	}
}

// --- extractTarGz: tar.gz totalSize exceeded ----------------------------

func TestExtractTarGzTotalSizeExceeded(t *testing.T) {
	bigFile := make([]byte, 200)
	for i := range bigFile {
		bigFile[i] = 'T'
	}
	archive := buildTarGzArchive(t, map[string][]byte{
		"a.bin": bigFile,
		"b.bin": bigFile,
	})
	body := buildMultipartBody("BOUND", "payload.tar.gz", "application/gzip", archive)
	hPath, dPath := buildEximSpool(t, `multipart/mixed; boundary="BOUND"`, body)

	limits := DefaultLimits()
	limits.MaxExtractionSize = 250
	result, err := ParseSpoolMessage(hPath, dPath, limits)
	if err != nil {
		t.Fatalf("ParseSpoolMessage: %v", err)
	}
	defer func() {
		for _, p := range result.Parts {
			os.Remove(p.TempPath)
		}
	}()

	if !result.Partial || !strings.Contains(result.PartialReason, "total extraction size") {
		t.Errorf("expected total extraction size partial, got Partial=%v reason=%q", result.Partial, result.PartialReason)
	}
}

// --- extractZIP: zip with directory entries (should be skipped) ---------

func TestExtractZIPSkipsDirectoryEntries(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	// Create a directory entry.
	dh := &zip.FileHeader{Name: "subdir/", Method: zip.Store}
	dh.SetMode(os.ModeDir | 0755)
	if _, err := zw.CreateHeader(dh); err != nil {
		t.Fatal(err)
	}
	// Create a real file.
	f, err := zw.Create("subdir/file.txt")
	if err != nil {
		t.Fatal(err)
	}
	if _, writeErr := f.Write([]byte("content")); writeErr != nil {
		t.Fatal(writeErr)
	}
	if closeErr := zw.Close(); closeErr != nil {
		t.Fatal(closeErr)
	}

	body := buildMultipartBody("BOUND", "dirs.zip", "application/zip", buf.Bytes())
	hPath, dPath := buildEximSpool(t, `multipart/mixed; boundary="BOUND"`, body)

	result, err := ParseSpoolMessage(hPath, dPath, DefaultLimits())
	if err != nil {
		t.Fatalf("ParseSpoolMessage: %v", err)
	}
	defer func() {
		for _, p := range result.Parts {
			os.Remove(p.TempPath)
		}
	}()

	// Only the actual file should be extracted, not the directory entry.
	nestedCount := 0
	for _, p := range result.Parts {
		if p.Nested {
			nestedCount++
		}
	}
	if nestedCount != 1 {
		t.Errorf("expected 1 nested file (skipping dir), got %d", nestedCount)
	}
}

// --- extractTarGz: tar with non-regular file entries --------------------

func TestExtractTarGzSkipsNonRegularFiles(t *testing.T) {
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)

	// Directory entry.
	if err := tw.WriteHeader(&tar.Header{
		Name:     "mydir/",
		Typeflag: tar.TypeDir,
		Mode:     0755,
	}); err != nil {
		t.Fatal(err)
	}

	// Symlink entry.
	if err := tw.WriteHeader(&tar.Header{
		Name:     "link.txt",
		Typeflag: tar.TypeSymlink,
		Linkname: "target.txt",
	}); err != nil {
		t.Fatal(err)
	}

	// Regular file.
	data := []byte("regular content")
	if err := tw.WriteHeader(&tar.Header{
		Name:     "real.txt",
		Typeflag: tar.TypeReg,
		Size:     int64(len(data)),
		Mode:     0644,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(data); err != nil {
		t.Fatal(err)
	}

	_ = tw.Close()
	_ = gw.Close()

	body := buildMultipartBody("BOUND", "mixed.tar.gz", "application/gzip", buf.Bytes())
	hPath, dPath := buildEximSpool(t, `multipart/mixed; boundary="BOUND"`, body)

	result, err := ParseSpoolMessage(hPath, dPath, DefaultLimits())
	if err != nil {
		t.Fatalf("ParseSpoolMessage: %v", err)
	}
	defer func() {
		for _, p := range result.Parts {
			os.Remove(p.TempPath)
		}
	}()

	nestedCount := 0
	for _, p := range result.Parts {
		if p.Nested && p.ArchiveName == "mixed.tar.gz" {
			nestedCount++
		}
	}
	if nestedCount != 1 {
		t.Errorf("expected 1 nested file (only regular), got %d", nestedCount)
	}
}

// TestExtractZIPSanitizesEntryName: a zip whose entry name contains
// path-traversal segments, an absolute path, or control characters
// must surface with only the base name. Operators see the sanitized
// name in audit logs and downstream consumers (UI, webhooks) cannot
// be tricked into joining the raw name into a path.
func TestExtractZIPSanitizesEntryName(t *testing.T) {
	cases := []struct {
		name    string
		entry   string
		wantBad []string
		want    string
	}{
		{
			name:    "path traversal",
			entry:   "../../../../etc/passwd",
			wantBad: []string{"..", "/"},
			want:    "passwd",
		},
		{
			name:    "absolute path",
			entry:   "/etc/shadow",
			wantBad: []string{"/"},
			want:    "shadow",
		},
		{
			name:    "newline injection",
			entry:   "good.txt\nFAKE-LOG-LINE",
			wantBad: []string{"\n"},
			want:    "good.txt",
		},
		{
			name:    "unicode control injection",
			entry:   "good.txt\u0085FAKE-LOG-LINE",
			wantBad: []string{"\u0085"},
			want:    "good.txt",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			archive := buildZipArchive(t, map[string][]byte{tc.entry: []byte("payload")})
			body := buildMultipartBody("BOUND", "evil.zip", "application/zip", archive)
			hPath, dPath := buildEximSpool(t, `multipart/mixed; boundary="BOUND"`, body)

			result, err := ParseSpoolMessage(hPath, dPath, DefaultLimits())
			if err != nil {
				t.Fatalf("ParseSpoolMessage: %v", err)
			}
			defer func() {
				for _, p := range result.Parts {
					_ = os.Remove(p.TempPath)
				}
			}()
			var nested *ExtractedPart
			for i := range result.Parts {
				if result.Parts[i].Nested {
					nested = &result.Parts[i]
					break
				}
			}
			if nested == nil {
				t.Fatalf("expected one nested part, got %d total parts", len(result.Parts))
			}
			for _, bad := range tc.wantBad {
				if strings.Contains(nested.Filename, bad) {
					t.Errorf("Filename %q must not contain %q", nested.Filename, bad)
				}
			}
			if nested.Filename != tc.want {
				t.Errorf("Filename = %q, want %q", nested.Filename, tc.want)
			}
		})
	}
}

func TestExtractTarGzSanitizesEntryName(t *testing.T) {
	archive := buildTarGzArchive(t, map[string][]byte{
		"..\\..\\report.txt\rFORGED": []byte("payload"),
	})
	body := buildMultipartBody("BOUND", "evil.tar.gz", "application/gzip", archive)
	hPath, dPath := buildEximSpool(t, `multipart/mixed; boundary="BOUND"`, body)

	result, err := ParseSpoolMessage(hPath, dPath, DefaultLimits())
	if err != nil {
		t.Fatalf("ParseSpoolMessage: %v", err)
	}
	defer func() {
		for _, p := range result.Parts {
			_ = os.Remove(p.TempPath)
		}
	}()

	var nested *ExtractedPart
	for i := range result.Parts {
		if result.Parts[i].Nested {
			nested = &result.Parts[i]
			break
		}
	}
	if nested == nil {
		t.Fatalf("expected one nested part, got %d total parts", len(result.Parts))
	}
	if nested.Filename != "report.txt" {
		t.Errorf("Filename = %q, want report.txt", nested.Filename)
	}
	for _, bad := range []string{"..", "\\", "\r"} {
		if strings.Contains(nested.Filename, bad) {
			t.Errorf("Filename %q must not contain %q", nested.Filename, bad)
		}
	}
}

func TestExtractMultipartSanitizesAttachmentFilenameAndArchiveName(t *testing.T) {
	archive := buildZipArchive(t, map[string][]byte{
		"inner.txt": []byte("payload"),
	})
	body := buildMultipartBody("BOUND", "..\\\\..\\\\unsafe.zip", "application/zip", archive)
	hPath, dPath := buildEximSpool(t, `multipart/mixed; boundary="BOUND"`, body)

	result, err := ParseSpoolMessage(hPath, dPath, DefaultLimits())
	if err != nil {
		t.Fatalf("ParseSpoolMessage: %v", err)
	}
	defer func() {
		for _, p := range result.Parts {
			_ = os.Remove(p.TempPath)
		}
	}()

	var outer, nested *ExtractedPart
	for i := range result.Parts {
		switch {
		case !result.Parts[i].Nested && result.Parts[i].Filename == "unsafe.zip":
			outer = &result.Parts[i]
		case result.Parts[i].Nested:
			nested = &result.Parts[i]
		}
	}
	if outer == nil {
		t.Fatalf("expected sanitized outer archive part, got %+v", result.Parts)
	}
	if nested == nil {
		t.Fatalf("expected nested archive part, got %+v", result.Parts)
	}
	if nested.ArchiveName != "unsafe.zip" {
		t.Errorf("ArchiveName = %q, want unsafe.zip", nested.ArchiveName)
	}
	for _, name := range []string{outer.Filename, nested.ArchiveName} {
		for _, bad := range []string{"..", "\\"} {
			if strings.Contains(name, bad) {
				t.Errorf("sanitized name %q must not contain %q", name, bad)
			}
		}
	}
}

func TestExtractMultipartDetectsArchiveWithControlBeforeExtension(t *testing.T) {
	archive := buildZipArchive(t, map[string][]byte{
		"inner.txt": []byte("payload"),
	})
	body := buildMultipartBody("BOUND", "payload\u0085.zip", "application/octet-stream", archive)
	hPath, dPath := buildEximSpool(t, `multipart/mixed; boundary="BOUND"`, body)

	result, err := ParseSpoolMessage(hPath, dPath, DefaultLimits())
	if err != nil {
		t.Fatalf("ParseSpoolMessage: %v", err)
	}
	defer func() {
		for _, p := range result.Parts {
			_ = os.Remove(p.TempPath)
		}
	}()

	hasNested := false
	for _, p := range result.Parts {
		if p.Nested && p.Filename == "inner.txt" {
			hasNested = true
			if strings.Contains(p.ArchiveName, "\u0085") {
				t.Errorf("ArchiveName %q must not contain control characters", p.ArchiveName)
			}
		}
	}
	if !hasNested {
		t.Fatalf("expected nested zip part despite control character before extension, got %+v", result.Parts)
	}
}

// --- extractMultipart: depth limit prevents nested archive extraction ---

func TestExtractZIPDepthLimitPreventsNesting(t *testing.T) {
	archive := buildZipArchive(t, map[string][]byte{
		"nested.txt": []byte("hello"),
	})
	body := buildMultipartBody("BOUND", "payload.zip", "application/zip", archive)
	hPath, dPath := buildEximSpool(t, `multipart/mixed; boundary="BOUND"`, body)

	limits := DefaultLimits()
	limits.MaxArchiveDepth = 0 // prevent any nesting
	result, err := ParseSpoolMessage(hPath, dPath, limits)
	if err != nil {
		t.Fatalf("ParseSpoolMessage: %v", err)
	}
	defer func() {
		for _, p := range result.Parts {
			os.Remove(p.TempPath)
		}
	}()

	// The outer .zip should be extracted, but nested.txt should NOT.
	for _, p := range result.Parts {
		if p.Filename == "nested.txt" && p.Nested {
			t.Error("depth=0 should prevent nested archive extraction")
		}
	}
}

// --- detectDirection: auth= prefix variant ------------------------------

func TestDetectDirectionAuthEquals(t *testing.T) {
	hdrs := map[string][]string{
		"Received": {"from [10.0.0.1] by mx (auth=plain user=bob)"},
	}
	if got := detectDirection(hdrs); got != "outbound" {
		t.Errorf("auth= in Received = %q, want outbound", got)
	}
}

// --- decodeSinglePart: empty input --------------------------------------

func TestDecodeSinglePartEmptyInput(t *testing.T) {
	got, truncated := decodeSinglePart([]byte{}, "7bit", 1024)
	if truncated {
		t.Error("empty input should not be truncated")
	}
	if len(got) != 0 {
		t.Errorf("got len %d, want 0", len(got))
	}
}

// --- ParseSpoolMessage: single-part attachment over size limit ----------

func TestParseSinglePartAttachmentOverSizeLimit(t *testing.T) {
	dir := t.TempDir()
	hPath := filepath.Join(dir, "msg-H")
	dPath := filepath.Join(dir, "msg-D")

	bigPayload := make([]byte, 200)
	for i := range bigPayload {
		bigPayload[i] = 'B'
	}
	encoded := base64.StdEncoding.EncodeToString(bigPayload)

	header := "Exim message header file\nmsgid-Y\n" +
		"From: x@y.com\nTo: a@b.com\nSubject: big\nMIME-Version: 1.0\n" +
		"Content-Type: application/pdf; name=\"big.pdf\"\n" +
		"Content-Transfer-Encoding: base64\n\n"
	if err := os.WriteFile(hPath, []byte(header), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dPath, []byte(encoded), 0644); err != nil {
		t.Fatal(err)
	}

	limits := DefaultLimits()
	limits.MaxAttachmentSize = 50
	result, err := ParseSpoolMessage(hPath, dPath, limits)
	if err != nil {
		t.Fatalf("ParseSpoolMessage: %v", err)
	}
	defer func() {
		for _, p := range result.Parts {
			os.Remove(p.TempPath)
		}
	}()

	if !result.Partial {
		t.Error("single-part attachment over limit should set Partial=true")
	}
	if len(result.Parts) != 0 {
		t.Errorf("oversized single-part should not be in Parts, got %d", len(result.Parts))
	}
}

// --- ParseSpoolMessage: Content-Disposition filename extraction ----------

func TestExtractMultipartFilenameFromContentDisposition(t *testing.T) {
	boundary := "BOUND"
	payload := []byte("malicious content")
	encoded := base64.StdEncoding.EncodeToString(payload)

	// Attachment has filename in Content-Disposition but NOT in Content-Type.
	body := "--" + boundary + "\r\n" +
		"Content-Type: text/plain\r\n\r\n" +
		"Body text.\r\n" +
		"--" + boundary + "\r\n" +
		"Content-Type: application/octet-stream\r\n" +
		"Content-Transfer-Encoding: base64\r\n" +
		"Content-Disposition: attachment; filename=\"from-disp.bin\"\r\n\r\n" +
		encoded + "\r\n" +
		"--" + boundary + "--\r\n"

	hPath, dPath := buildEximSpool(t, `multipart/mixed; boundary="BOUND"`, body)
	result, err := ParseSpoolMessage(hPath, dPath, DefaultLimits())
	if err != nil {
		t.Fatalf("ParseSpoolMessage: %v", err)
	}
	defer func() {
		for _, p := range result.Parts {
			os.Remove(p.TempPath)
		}
	}()

	found := false
	for _, p := range result.Parts {
		if p.Filename == "from-disp.bin" {
			found = true
		}
	}
	if !found {
		names := make([]string, len(result.Parts))
		for i, p := range result.Parts {
			names[i] = p.Filename
		}
		t.Errorf("expected filename from Content-Disposition, got %v", names)
	}
}
