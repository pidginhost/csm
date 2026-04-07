package wpcheck

import (
	"testing"
)

func TestParseChecksumResponse(t *testing.T) {
	validJSON := []byte(`{
		"checksums": {
			"wp-includes/version.php": "abc123def456",
			"wp-includes/Text/Diff/Engine/shell.php": "7443bb26aa932003ba7742d0e64007c6",
			"wp-admin/index.php": "fedcba987654"
		}
	}`)

	checksums, err := ParseChecksumResponse(validJSON)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(checksums) != 3 {
		t.Fatalf("expected 3 checksums, got %d", len(checksums))
	}
	if checksums["wp-includes/Text/Diff/Engine/shell.php"] != "7443bb26aa932003ba7742d0e64007c6" {
		t.Errorf("unexpected checksum for shell.php: %s", checksums["wp-includes/Text/Diff/Engine/shell.php"])
	}
}

func TestParseChecksumResponseErrors(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{"empty", []byte("")},
		{"invalid json", []byte("{not json")},
		{"missing checksums key", []byte(`{"version": "6.9.4"}`)},
		{"null checksums", []byte(`{"checksums": null}`)},
		{"empty checksums", []byte(`{"checksums": {}}`)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseChecksumResponse(tt.data)
			if err == nil {
				t.Error("expected error, got nil")
			}
		})
	}
}
