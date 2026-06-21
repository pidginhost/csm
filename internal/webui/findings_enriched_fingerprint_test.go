package webui

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestEnrichedFindingDTOCarriesContentSHA256 verifies the enrichedFinding DTO
// serialises content_sha256 so the JS frontend can read it back for Re-check.
//
// Approach: marshal enrichedFinding{ContentSHA256: "abc123"} directly and assert
// the output contains `"content_sha256":"abc123"`. This is the simplest contract
// test: it doesn't require a store or HTTP harness, and the field is what the JS
// depends on — if it's missing or misspelled the test fails immediately.
func TestEnrichedFindingDTOCarriesContentSHA256(t *testing.T) {
	ef := enrichedFinding{
		Key:           "webshell:Known webshell found: /home/u/shell.php",
		Check:         "webshell",
		Message:       "Known webshell found: /home/u/shell.php",
		ContentSHA256: "abc123deadbeef",
	}
	b, err := json.Marshal(ef)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	got := string(b)
	want := `"content_sha256":"abc123deadbeef"`
	if !strings.Contains(got, want) {
		t.Errorf("DTO JSON missing %q\ngot: %s", want, got)
	}
}

// TestEnrichedFindingDTOOmitsEmptyContentSHA256 verifies that when no
// ContentSHA256 is set (most findings) the field is omitted, keeping the
// response payload compact.
func TestEnrichedFindingDTOOmitsEmptyContentSHA256(t *testing.T) {
	ef := enrichedFinding{
		Key:     "brute_force:SSH from 198.51.100.7",
		Check:   "brute_force",
		Message: "SSH from 198.51.100.7",
	}
	b, err := json.Marshal(ef)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	got := string(b)
	if strings.Contains(got, "content_sha256") {
		t.Errorf("DTO JSON should omit content_sha256 when empty\ngot: %s", got)
	}
}
