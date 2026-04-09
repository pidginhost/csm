package signatures

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReloadRejectsParseFailureAndPreservesExistingRules(t *testing.T) {
	dir := t.TempDir()
	valid := `
version: 1
rules:
  - name: ok_rule
    description: "ok"
    severity: high
    category: webshell
    file_types: [".php"]
    patterns: ["eval("]
`
	if err := os.WriteFile(filepath.Join(dir, "rules.yml"), []byte(valid), 0644); err != nil {
		t.Fatal(err)
	}

	scanner := NewScanner(dir)
	if scanner.RuleCount() != 1 {
		t.Fatalf("expected initial rules to load, got %d", scanner.RuleCount())
	}

	invalid := "version: [\nrules:\n"
	if err := os.WriteFile(filepath.Join(dir, "rules.yml"), []byte(invalid), 0644); err != nil {
		t.Fatal(err)
	}

	if err := scanner.Reload(); err == nil {
		t.Fatal("expected reload error for invalid yaml")
	}
	if scanner.RuleCount() != 1 {
		t.Fatalf("expected existing rules to be preserved, got %d", scanner.RuleCount())
	}
}
