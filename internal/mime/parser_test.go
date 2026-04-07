package mime

import (
	"os"
	"path/filepath"
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
