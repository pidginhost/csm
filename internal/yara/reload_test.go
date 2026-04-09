//go:build yara

package yara

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReloadRejectsInvalidRulesAndPreservesExistingSet(t *testing.T) {
	dir := t.TempDir()
	validRule := `rule good_rule { condition: true }`
	rulePath := filepath.Join(dir, "test.yar")
	if err := os.WriteFile(rulePath, []byte(validRule), 0644); err != nil {
		t.Fatal(err)
	}

	scanner, err := NewScanner(dir)
	if err != nil {
		t.Fatalf("initial load failed: %v", err)
	}
	if scanner.RuleCount() == 0 {
		t.Fatal("expected initial rules to load")
	}

	invalidRule := `rule broken_rule { condition:`
	if err := os.WriteFile(rulePath, []byte(invalidRule), 0644); err != nil {
		t.Fatal(err)
	}

	if err := scanner.Reload(); err == nil {
		t.Fatal("expected reload error for invalid yara source")
	}
	if scanner.RuleCount() == 0 {
		t.Fatal("expected previous rules to remain active")
	}
}
