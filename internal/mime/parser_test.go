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

	// Cleanup
	for _, p := range result.Parts {
		os.Remove(p.TempPath)
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

	header := "malware\ntest@example.com\nuser@example.com\n0\n0\n" +
		"Content-Type: application/octet-stream; name=\"huge.bin\"\n" +
		"Content-Transfer-Encoding: base64\n\n"
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
