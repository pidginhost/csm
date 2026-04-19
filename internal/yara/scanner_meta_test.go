//go:build yara

package yara

import (
	"os"
	"path/filepath"
	"testing"
)

// TestScanBytesPopulatesStringMetadata is the load-bearing contract for
// emailav severity lookup under worker mode: matches returned by the
// scanner must carry string-valued rule metadata. Without this,
// emailav would default every match to "high" regardless of rule
// author intent. Non-string metadata (here: numeric) must be dropped
// so the IPC wire format (map[string]string) stays honest.
func TestScanBytesPopulatesStringMetadata(t *testing.T) {
	dir := t.TempDir()
	source := `
rule emailav_severity_fixture {
    meta:
        severity = "critical"
        description = "fixture rule"
        numeric = 42
    strings:
        $m = "FIXTURE_MATCH_SENTINEL"
    condition:
        $m
}`
	if err := os.WriteFile(filepath.Join(dir, "fixture.yar"), []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}

	s, err := NewScanner(dir)
	if err != nil {
		t.Fatalf("NewScanner: %v", err)
	}
	matches := s.ScanBytes([]byte("prefix FIXTURE_MATCH_SENTINEL suffix"))
	if len(matches) != 1 {
		t.Fatalf("matches = %d, want 1", len(matches))
	}
	got := matches[0]
	if got.RuleName != "emailav_severity_fixture" {
		t.Errorf("RuleName = %q", got.RuleName)
	}
	if got.Meta["severity"] != "critical" {
		t.Errorf(`Meta["severity"] = %q, want "critical"`, got.Meta["severity"])
	}
	if got.Meta["description"] != "fixture rule" {
		t.Errorf(`Meta["description"] = %q, want "fixture rule"`, got.Meta["description"])
	}
	if _, ok := got.Meta["numeric"]; ok {
		t.Errorf("non-string metadata should be dropped; got Meta[numeric] = %v", got.Meta["numeric"])
	}
}

// TestScanBytesNoMetadataYieldsNilMap keeps the clean-scan allocation
// guarantee honest: a rule with no metadata must not force callers to
// handle a zero-length map when nil says the same thing more cheaply.
func TestScanBytesNoMetadataYieldsNilMap(t *testing.T) {
	dir := t.TempDir()
	source := `
rule no_meta_rule {
    strings:
        $m = "NOMETA_SENTINEL"
    condition:
        $m
}`
	if err := os.WriteFile(filepath.Join(dir, "fixture.yar"), []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := NewScanner(dir)
	if err != nil {
		t.Fatalf("NewScanner: %v", err)
	}
	matches := s.ScanBytes([]byte("NOMETA_SENTINEL"))
	if len(matches) != 1 {
		t.Fatalf("matches = %d, want 1", len(matches))
	}
	if matches[0].Meta != nil {
		t.Errorf("Meta = %v, want nil for rule without metadata", matches[0].Meta)
	}
}
