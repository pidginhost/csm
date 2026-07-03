package mime

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseSinglePart(t *testing.T) {
	hPath := filepath.Join("testdata", "simple-H")
	dPath := filepath.Join("testdata", "simple-D")

	result, err := ParseSpoolMessage(hPath, dPath, DefaultLimits())
	if err != nil {
		t.Fatalf("ParseSpoolMessage failed: %v", err)
	}

	if result.From != "sender@example.com" {
		t.Errorf("From = %q, want %q", result.From, "sender@example.com")
	}
	if result.Subject != "Test message" {
		t.Errorf("Subject = %q, want %q", result.Subject, "Test message")
	}
	if len(result.To) != 1 || result.To[0] != "user@domain.com" {
		t.Errorf("To = %v, want [user@domain.com]", result.To)
	}
	// Single text/plain body - no extractable attachments
	if len(result.Parts) != 0 {
		t.Errorf("Parts = %d, want 0 for text-only email", len(result.Parts))
	}
	if result.Partial {
		t.Error("Partial should be false for simple email")
	}
}

func TestParseMultipartWithAttachment(t *testing.T) {
	hPath := filepath.Join("testdata", "multipart-H")
	dPath := filepath.Join("testdata", "multipart-D")

	result, err := ParseSpoolMessage(hPath, dPath, DefaultLimits())
	if err != nil {
		t.Fatalf("ParseSpoolMessage failed: %v", err)
	}

	if result.From != "sender@external.com" {
		t.Errorf("From = %q, want %q", result.From, "sender@external.com")
	}
	if result.Direction != "inbound" {
		t.Errorf("Direction = %q, want %q", result.Direction, "inbound")
	}
	if len(result.Parts) != 1 {
		t.Fatalf("Parts = %d, want 1", len(result.Parts))
	}

	part := result.Parts[0]
	if part.Filename != "test.exe" {
		t.Errorf("Filename = %q, want %q", part.Filename, "test.exe")
	}
	if part.Size == 0 {
		t.Error("Size should be > 0 for decoded base64 attachment")
	}

	// Verify temp file exists and has content
	data, err := os.ReadFile(part.TempPath)
	if err != nil {
		t.Fatalf("reading temp file: %v", err)
	}
	if len(data) == 0 {
		t.Error("temp file should have decoded content")
	}

	// Cleanup
	for _, p := range result.Parts {
		os.Remove(p.TempPath)
	}
}

func TestParseMultipartUsesConfiguredTempDir(t *testing.T) {
	hPath := filepath.Join("testdata", "multipart-H")
	dPath := filepath.Join("testdata", "multipart-D")
	tempDir := t.TempDir()
	limits := DefaultLimits()
	limits.TempDir = tempDir

	result, err := ParseSpoolMessage(hPath, dPath, limits)
	if err != nil {
		t.Fatalf("ParseSpoolMessage failed: %v", err)
	}
	defer func() {
		for _, p := range result.Parts {
			os.Remove(p.TempPath)
		}
	}()

	if len(result.Parts) != 1 {
		t.Fatalf("Parts = %d, want 1", len(result.Parts))
	}
	if got := filepath.Dir(result.Parts[0].TempPath); got != tempDir {
		t.Fatalf("TempPath dir = %q, want %q", got, tempDir)
	}
}

func TestParseMultipartTempDirFailureMarksPartial(t *testing.T) {
	hPath := filepath.Join("testdata", "multipart-H")
	dPath := filepath.Join("testdata", "multipart-D")
	limits := DefaultLimits()
	limits.TempDir = filepath.Join(t.TempDir(), "missing")

	result, err := ParseSpoolMessage(hPath, dPath, limits)
	if err != nil {
		t.Fatalf("ParseSpoolMessage failed: %v", err)
	}

	if !result.Partial {
		t.Fatal("Partial = false, want true")
	}
	if result.PartialReason != "could not stage attachment for scanning" {
		t.Fatalf("PartialReason = %q", result.PartialReason)
	}
	if len(result.Parts) != 0 {
		t.Fatalf("Parts = %d, want 0", len(result.Parts))
	}
}

func TestParseLimitEnforcement(t *testing.T) {
	hPath := filepath.Join("testdata", "multipart-H")
	dPath := filepath.Join("testdata", "multipart-D")

	tiny := Limits{
		MaxAttachmentSize: 5, // 5 bytes - the base64-decoded exe will exceed this
		MaxArchiveDepth:   1,
		MaxArchiveFiles:   50,
		MaxExtractionSize: 100 * 1024 * 1024,
	}

	result, err := ParseSpoolMessage(hPath, dPath, tiny)
	if err != nil {
		t.Fatalf("ParseSpoolMessage failed: %v", err)
	}

	if len(result.Parts) != 0 {
		t.Errorf("Parts = %d, want 0 (attachment should be skipped)", len(result.Parts))
	}
	if !result.Partial {
		t.Error("Partial should be true when attachment exceeds limit")
	}

	// Cleanup
	for _, p := range result.Parts {
		os.Remove(p.TempPath)
	}
}

func TestParseOutboundDirection(t *testing.T) {
	hPath := filepath.Join("testdata", "simple-H")
	dPath := filepath.Join("testdata", "simple-D")

	result, err := ParseSpoolMessage(hPath, dPath, DefaultLimits())
	if err != nil {
		t.Fatalf("ParseSpoolMessage failed: %v", err)
	}

	// simple-H has no Received header, so outbound
	if result.Direction != "outbound" {
		t.Errorf("Direction = %q, want %q", result.Direction, "outbound")
	}
}

func TestParseSinglePartAttachment(t *testing.T) {
	hPath := filepath.Join("testdata", "singlepart-H")
	dPath := filepath.Join("testdata", "singlepart-D")

	result, err := ParseSpoolMessage(hPath, dPath, DefaultLimits())
	if err != nil {
		t.Fatalf("ParseSpoolMessage failed: %v", err)
	}

	// Single application/pdf - should be extracted as an attachment
	if len(result.Parts) != 1 {
		t.Fatalf("Parts = %d, want 1 for single-part PDF", len(result.Parts))
	}
	if result.Parts[0].ContentType != "application/pdf" {
		t.Errorf("ContentType = %q, want %q", result.Parts[0].ContentType, "application/pdf")
	}
	if result.Parts[0].Filename != "report.pdf" {
		t.Errorf("Filename = %q, want %q", result.Parts[0].Filename, "report.pdf")
	}
	if result.Parts[0].Size == 0 {
		t.Error("Size should be > 0 for decoded base64 content")
	}

	// MAIL-04: the -D message-id marker line must be stripped before decode,
	// otherwise the base64 payload is prefixed with "singlepart-D\n" and either
	// fails to decode or produces garbage. Assert the exact decoded bytes.
	data, err := os.ReadFile(result.Parts[0].TempPath)
	if err != nil {
		t.Fatalf("reading staged part: %v", err)
	}
	const wantPDF = "%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n"
	if string(data) != wantPDF {
		t.Errorf("decoded single-part content = %q, want %q", data, wantPDF)
	}

	// Cleanup
	for _, p := range result.Parts {
		os.Remove(p.TempPath)
	}
}

// MAIL-01: real Exim -H files prefix every RFC header with a decimal byte
// count and a flag character (e.g. "048F From: ..."). A parser that only
// recognizes bare "From:"/"Content-Type:" lines never enters its header
// section, returns empty headers, and reports zero attachments -- the email-AV
// pipeline goes inert against real mail. This asserts the length+flag prefix is
// understood using the real-format golden fixtures.
func TestParseEximRealHeaderFormatDetected(t *testing.T) {
	result, err := ParseSpoolMessage(
		filepath.Join("testdata", "multipart-H"),
		filepath.Join("testdata", "multipart-D"),
		DefaultLimits(),
	)
	if err != nil {
		t.Fatalf("ParseSpoolMessage failed: %v", err)
	}
	defer func() {
		for _, p := range result.Parts {
			os.Remove(p.TempPath)
		}
	}()

	if result.From != "sender@external.com" {
		t.Errorf("From = %q, want sender@external.com (length+flag prefix not parsed)", result.From)
	}
	if result.Subject != "Document attached" {
		t.Errorf("Subject = %q, want 'Document attached'", result.Subject)
	}
	if len(result.To) != 1 || result.To[0] != "user@domain.com" {
		t.Errorf("To = %v, want [user@domain.com]", result.To)
	}
	if result.Direction != "inbound" {
		t.Errorf("Direction = %q, want inbound (Received header not parsed)", result.Direction)
	}
	// Content-Type must be parsed from the prefixed header so the multipart
	// attachment is extracted.
	if len(result.Parts) != 1 || result.Parts[0].Filename != "test.exe" {
		t.Fatalf("Parts = %+v, want one test.exe attachment", result.Parts)
	}
}

func TestParseSinglePartTempDirFailureMarksPartial(t *testing.T) {
	hPath := filepath.Join("testdata", "singlepart-H")
	dPath := filepath.Join("testdata", "singlepart-D")
	limits := DefaultLimits()
	limits.TempDir = filepath.Join(t.TempDir(), "missing")

	result, err := ParseSpoolMessage(hPath, dPath, limits)
	if err != nil {
		t.Fatalf("ParseSpoolMessage failed: %v", err)
	}

	if !result.Partial {
		t.Fatal("Partial = false, want true")
	}
	if result.PartialReason != "could not stage single-part attachment for scanning" {
		t.Fatalf("PartialReason = %q", result.PartialReason)
	}
	if len(result.Parts) != 0 {
		t.Fatalf("Parts = %d, want 0", len(result.Parts))
	}
}

func TestParseSinglePartTextNotExtracted(t *testing.T) {
	hPath := filepath.Join("testdata", "simple-H")
	dPath := filepath.Join("testdata", "simple-D")

	result, err := ParseSpoolMessage(hPath, dPath, DefaultLimits())
	if err != nil {
		t.Fatalf("ParseSpoolMessage failed: %v", err)
	}

	// text/plain body should NOT be extracted as an attachment
	if len(result.Parts) != 0 {
		t.Errorf("Parts = %d, want 0 for text/plain body", len(result.Parts))
	}
}

func TestParseSpoolMessageCapsLargeBodyRead(t *testing.T) {
	dir := t.TempDir()
	hPath := filepath.Join(dir, "large-H")
	dPath := filepath.Join(dir, "large-D")

	header := "large-H\ncpuser 1000 1000\n<test@example.com>\n0 0\n-local\n1\nuser@example.com\n\n" +
		eximHdr(' ', `Content-Type: application/octet-stream; name="huge.bin"`) +
		eximHdr(' ', "Content-Transfer-Encoding: base64")
	if err := os.WriteFile(hPath, []byte(header), 0600); err != nil {
		t.Fatal(err)
	}

	payload := strings.Repeat("A", 1024)
	body := base64.StdEncoding.EncodeToString([]byte(payload))
	body = strings.Repeat(body, 4096)
	if err := os.WriteFile(dPath, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}

	limits := Limits{
		MaxAttachmentSize: 1024,
		MaxArchiveDepth:   1,
		MaxArchiveFiles:   10,
		MaxExtractionSize: 2048,
	}

	result, err := ParseSpoolMessage(hPath, dPath, limits)
	if err != nil {
		t.Fatalf("ParseSpoolMessage failed: %v", err)
	}
	if !result.Partial {
		t.Fatal("expected parser to mark oversized body as partial")
	}
	if len(result.Parts) != 0 {
		t.Fatalf("Parts = %d, want 0 for oversized body budget", len(result.Parts))
	}
}
