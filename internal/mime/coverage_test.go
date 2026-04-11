package mime

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// --- bodyReadLimit edge cases ------------------------------------------

func TestBodyReadLimitZeroFallsBackToDefault(t *testing.T) {
	got := bodyReadLimit(Limits{})
	if got != DefaultLimits().MaxExtractionSize {
		t.Errorf("got %d, want %d (default)", got, DefaultLimits().MaxExtractionSize)
	}
}

func TestBodyReadLimitScalesUpWhenExtractionSmallerThan2xAttachment(t *testing.T) {
	l := Limits{MaxAttachmentSize: 10 << 20, MaxExtractionSize: 5 << 20}
	got := bodyReadLimit(l)
	if got != 20<<20 {
		t.Errorf("got %d, want %d (2x attachment)", got, 20<<20)
	}
}

func TestBodyReadLimitUsesExtractionWhenLarger(t *testing.T) {
	l := Limits{MaxAttachmentSize: 1 << 20, MaxExtractionSize: 100 << 20}
	got := bodyReadLimit(l)
	if got != 100<<20 {
		t.Errorf("got %d, want %d", got, 100<<20)
	}
}

// --- readFileLimited ---------------------------------------------------

func TestReadFileLimitedOK(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ok.txt")
	if err := os.WriteFile(path, []byte("hello world"), 0644); err != nil {
		t.Fatal(err)
	}
	data, err := readFileLimited(path, 1024)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "hello world" {
		t.Errorf("got %q", data)
	}
}

func TestReadFileLimitedMissingFile(t *testing.T) {
	_, err := readFileLimited(filepath.Join(t.TempDir(), "no.txt"), 1024)
	if err == nil {
		t.Fatal("missing file should error")
	}
}

func TestReadFileLimitedExceedsLimit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "big.txt")
	if err := os.WriteFile(path, make([]byte, 200), 0644); err != nil {
		t.Fatal(err)
	}
	_, err := readFileLimited(path, 100)
	if err == nil || !strings.Contains(err.Error(), "exceeds parser memory budget") {
		t.Errorf("err = %v, want 'exceeds parser memory budget'", err)
	}
}

// --- decodeSinglePart --------------------------------------------------

func TestDecodeSinglePartBase64(t *testing.T) {
	plain := []byte("Hello, World!")
	encoded := base64.StdEncoding.EncodeToString(plain)
	got, truncated := decodeSinglePart([]byte(encoded), "base64", 1024)
	if truncated {
		t.Error("should not be truncated for small input")
	}
	if !bytes.Equal(got, plain) {
		t.Errorf("got %q, want %q", got, plain)
	}
}

func TestDecodeSinglePartQuotedPrintable(t *testing.T) {
	got, truncated := decodeSinglePart([]byte("Hello=20World"), "quoted-printable", 1024)
	if truncated {
		t.Error("should not be truncated")
	}
	if string(got) != "Hello World" {
		t.Errorf("got %q, want Hello World", got)
	}
}

func TestDecodeSinglePart7bitPassthrough(t *testing.T) {
	got, truncated := decodeSinglePart([]byte("raw text"), "7bit", 1024)
	if truncated {
		t.Error("should not be truncated")
	}
	if string(got) != "raw text" {
		t.Errorf("got %q", got)
	}
}

func TestDecodeSinglePart7bitTruncated(t *testing.T) {
	big := make([]byte, 200)
	for i := range big {
		big[i] = 'x'
	}
	got, truncated := decodeSinglePart(big, "7bit", 50)
	if !truncated {
		t.Error("should be truncated")
	}
	if len(got) != 50 {
		t.Errorf("got len %d, want 50", len(got))
	}
}

func TestDecodeSinglePartBase64Oversized(t *testing.T) {
	// Decoded size will be ~150 bytes; limit to 50 → truncated.
	raw := make([]byte, 200)
	for i := range raw {
		raw[i] = 'A'
	}
	encoded := base64.StdEncoding.EncodeToString(raw)
	got, truncated := decodeSinglePart([]byte(encoded), "base64", 50)
	if !truncated {
		t.Error("should be truncated")
	}
	if len(got) != 50 {
		t.Errorf("len %d, want 50", len(got))
	}
}

// --- extractZIP via ParseSpoolMessage ---------------------------------

// buildEximSpool writes a mock Exim -H / -D file pair for ParseSpoolMessage.
func buildEximSpool(t *testing.T, contentType, body string) (hPath, dPath string) {
	t.Helper()
	dir := t.TempDir()
	hPath = filepath.Join(dir, "msg-H")
	dPath = filepath.Join(dir, "msg-D")

	// Minimal Exim -H structure: metadata lines then RFC headers.
	header := "Exim message header file\n" +
		"msgid-1Z\n" +
		"Received: from [10.0.0.1] by test with esmtp for user@domain.com; Mon, 01 Jan 2026 00:00:00 +0000\n" +
		"From: attacker@external.com\n" +
		"To: user@domain.com\n" +
		"Subject: archive test\n" +
		"MIME-Version: 1.0\n" +
		"Content-Type: " + contentType + "\n" +
		"\n"
	if err := os.WriteFile(hPath, []byte(header), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dPath, []byte(body), 0644); err != nil {
		t.Fatal(err)
	}
	return hPath, dPath
}

// buildZipArchive returns a ZIP byte slice containing the given file entries.
func buildZipArchive(t *testing.T, files map[string][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, data := range files {
		f, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func buildTarGzArchive(t *testing.T, files map[string][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)
	for name, data := range files {
		hdr := &tar.Header{Name: name, Size: int64(len(data)), Mode: 0644}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	_ = tw.Close()
	_ = gw.Close()
	return buf.Bytes()
}

func buildMultipartBody(boundary, filename, cType string, payload []byte) string {
	encoded := base64.StdEncoding.EncodeToString(payload)
	// Wrap base64 at 76 cols as RFC 2045 specifies — encoders often do this.
	var wrapped strings.Builder
	for i := 0; i < len(encoded); i += 76 {
		end := i + 76
		if end > len(encoded) {
			end = len(encoded)
		}
		wrapped.WriteString(encoded[i:end])
		wrapped.WriteString("\r\n")
	}
	return "--" + boundary + "\r\n" +
		"Content-Type: text/plain\r\n\r\n" +
		"See attachment.\r\n" +
		"--" + boundary + "\r\n" +
		"Content-Type: " + cType + "; name=\"" + filename + "\"\r\n" +
		"Content-Transfer-Encoding: base64\r\n" +
		"Content-Disposition: attachment; filename=\"" + filename + "\"\r\n\r\n" +
		wrapped.String() + "\r\n" +
		"--" + boundary + "--\r\n"
}

func TestExtractZIP(t *testing.T) {
	archive := buildZipArchive(t, map[string][]byte{
		"inner.txt":        []byte("hello from the zip"),
		"subdir/other.bin": {0x01, 0x02, 0x03, 0x04},
	})
	body := buildMultipartBody("BOUND", "payload.zip", "application/zip", archive)
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

	// Expect at least the outer .zip AND its contents extracted.
	hasZIP := false
	hasInner := false
	for _, p := range result.Parts {
		if p.Filename == "payload.zip" {
			hasZIP = true
		}
		if p.Filename == "inner.txt" && p.Nested && p.ArchiveName == "payload.zip" {
			hasInner = true
		}
	}
	if !hasZIP {
		t.Error("outer ZIP attachment should be in Parts")
	}
	if !hasInner {
		t.Errorf("inner.txt from ZIP should be extracted; parts=%+v", result.Parts)
	}
}

func TestExtractZIPCorruptArchive(t *testing.T) {
	// A .zip attachment whose bytes are not actually a ZIP.
	body := buildMultipartBody("BOUND", "corrupt.zip", "application/zip", []byte("not a real zip"))
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
	// Outer file should still be present, but no extracted children.
	count := 0
	for _, p := range result.Parts {
		if p.Nested {
			count++
		}
	}
	if count != 0 {
		t.Errorf("corrupt ZIP should yield 0 nested parts, got %d", count)
	}
}

func TestExtractZIPExceedsMaxFiles(t *testing.T) {
	files := map[string][]byte{}
	for i := 0; i < 5; i++ {
		files[filepath.Join("entry", "f"+string(rune('a'+i))+".txt")] = []byte("x")
	}
	archive := buildZipArchive(t, files)
	body := buildMultipartBody("BOUND", "many.zip", "application/zip", archive)
	hPath, dPath := buildEximSpool(t, `multipart/mixed; boundary="BOUND"`, body)

	limits := DefaultLimits()
	limits.MaxArchiveFiles = 2
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
		t.Errorf("Partial should be true when archive exceeds MaxArchiveFiles")
	}
	if !strings.Contains(result.PartialReason, "exceeds max files") {
		t.Errorf("PartialReason = %q", result.PartialReason)
	}
}

func TestExtractTarGz(t *testing.T) {
	archive := buildTarGzArchive(t, map[string][]byte{
		"inside.txt":      []byte("tgz contents here"),
		"nested/file.bin": {0xAA, 0xBB},
	})
	body := buildMultipartBody("BOUND", "payload.tar.gz", "application/gzip", archive)
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

	hasTgz := false
	hasInner := false
	for _, p := range result.Parts {
		if p.Filename == "payload.tar.gz" {
			hasTgz = true
		}
		if p.Filename == "inside.txt" && p.Nested && p.ArchiveName == "payload.tar.gz" {
			hasInner = true
		}
	}
	if !hasTgz {
		t.Error("outer .tar.gz should be present")
	}
	if !hasInner {
		t.Errorf("inside.txt from tar.gz should be extracted; parts=%+v", result.Parts)
	}
}

func TestExtractTarGzCorruptArchive(t *testing.T) {
	body := buildMultipartBody("BOUND", "broken.tar.gz", "application/gzip", []byte("not gzip"))
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

	count := 0
	for _, p := range result.Parts {
		if p.Nested {
			count++
		}
	}
	if count != 0 {
		t.Errorf("corrupt tar.gz should yield 0 nested parts, got %d", count)
	}
}

// --- extra extraction branches ----------------------------------------

func TestExtractTarGzExceedsMaxFiles(t *testing.T) {
	files := map[string][]byte{}
	for i := 0; i < 5; i++ {
		files["f"+string(rune('a'+i))+".txt"] = []byte("x")
	}
	archive := buildTarGzArchive(t, files)
	body := buildMultipartBody("BOUND", "many.tar.gz", "application/gzip", archive)
	hPath, dPath := buildEximSpool(t, `multipart/mixed; boundary="BOUND"`, body)

	limits := DefaultLimits()
	limits.MaxArchiveFiles = 2
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
		t.Error("Partial should be true when tar.gz exceeds MaxArchiveFiles")
	}
}

func TestExtractZIPTotalSizeExceeded(t *testing.T) {
	// Put a few small files inside, but set MaxExtractionSize very low so
	// the running total blows up after the first entry.
	big := make([]byte, 200)
	for i := range big {
		big[i] = 'X'
	}
	archive := buildZipArchive(t, map[string][]byte{
		"first.bin":  big,
		"second.bin": big,
	})
	body := buildMultipartBody("BOUND", "bulk.zip", "application/zip", archive)
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

func TestDetectDirectionOutboundNoReceived(t *testing.T) {
	hdrs := make(map[string][]string)
	// No Received headers at all → outbound
	if got := detectDirection(hdrs); got != "outbound" {
		t.Errorf("no Received headers = %q, want outbound", got)
	}
}

func TestDetectDirectionOutboundAuthenticated(t *testing.T) {
	hdrs := map[string][]string{
		"Received": {"from [10.0.0.1] (authenticated user=alice) by mx"},
	}
	if got := detectDirection(hdrs); got != "outbound" {
		t.Errorf("authenticated = %q, want outbound", got)
	}
}

func TestDetectDirectionInbound(t *testing.T) {
	hdrs := map[string][]string{
		"Received": {"from [203.0.113.1] by mx with esmtp"},
	}
	if got := detectDirection(hdrs); got != "inbound" {
		t.Errorf("unauth = %q, want inbound", got)
	}
}

// --- ParseSpoolMessage error branches ---------------------------------

func TestParseSpoolMessageMissingHeaderFile(t *testing.T) {
	_, err := ParseSpoolMessage(
		filepath.Join(t.TempDir(), "missing-H"),
		filepath.Join(t.TempDir(), "missing-D"),
		DefaultLimits(),
	)
	if err == nil {
		t.Fatal("missing header file should error")
	}
}

func TestParseSpoolMessageMissingBodyFile(t *testing.T) {
	hPath := filepath.Join(t.TempDir(), "msg-H")
	hdr := "Exim message header file\nmsgid-X\nFrom: x@y\nTo: a@b\nSubject: s\nMIME-Version: 1.0\nContent-Type: text/plain\n\n"
	if err := os.WriteFile(hPath, []byte(hdr), 0644); err != nil {
		t.Fatal(err)
	}
	_, err := ParseSpoolMessage(hPath, filepath.Join(t.TempDir(), "missing-D"), DefaultLimits())
	if err == nil {
		t.Fatal("missing body file should error")
	}
}

func TestParseSpoolMessageBodyExceedsLimit(t *testing.T) {
	hPath, dPath := buildEximSpool(t, "text/plain", strings.Repeat("a", 1000))
	tiny := Limits{MaxAttachmentSize: 10, MaxArchiveDepth: 1, MaxArchiveFiles: 5, MaxExtractionSize: 100}
	result, err := ParseSpoolMessage(hPath, dPath, tiny)
	if err != nil {
		t.Fatalf("ParseSpoolMessage: %v", err)
	}
	if !result.Partial {
		t.Error("Partial should be true when body exceeds parser limit")
	}
}

func TestParseSpoolMessageMultipartMissingBoundaryTreatedAsEmpty(t *testing.T) {
	hPath, dPath := buildEximSpool(t, "multipart/mixed", "body")
	result, err := ParseSpoolMessage(hPath, dPath, DefaultLimits())
	if err != nil {
		t.Fatalf("ParseSpoolMessage: %v", err)
	}
	if len(result.Parts) != 0 {
		t.Errorf("multipart without boundary should produce 0 parts, got %d", len(result.Parts))
	}
}

func TestParseSpoolMessageUnparseableContentType(t *testing.T) {
	hPath, dPath := buildEximSpool(t, "this is / not valid", "body")
	result, err := ParseSpoolMessage(hPath, dPath, DefaultLimits())
	if err != nil {
		t.Fatalf("ParseSpoolMessage: %v", err)
	}
	if len(result.Parts) != 0 {
		t.Errorf("unparseable content type should skip extraction, got %d parts", len(result.Parts))
	}
}
