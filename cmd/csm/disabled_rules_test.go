package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A name nobody recognises reads as "that rule is off" while the rule keeps
// firing, so validation has to say so.
func TestValidateDisabledRulesReportsUnknownNames(t *testing.T) {
	dir := t.TempDir()
	rules := `version: 1
rules:
  - name: sample_rule
    description: "test"
    severity: high
    category: webshell
    file_types: [".php"]
    patterns: ["needle"]
    min_match: 1
`
	if err := os.WriteFile(filepath.Join(dir, "malware.yml"), []byte(rules), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "extra.yar"), []byte("rule yara_sample {\n  condition:\n    false\n}\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	results := validateDisabledRules(dir, []string{"sample_rule", "yara_sample", "typo_rule"})
	var warned, okd bool
	for _, r := range results {
		switch r.Level {
		case "warn":
			warned = true
			if !strings.Contains(r.Message, "typo_rule") {
				t.Errorf("warning does not name the unknown rule: %q", r.Message)
			}
			if strings.Contains(r.Message, "sample_rule") || strings.Contains(r.Message, "yara_sample") {
				t.Errorf("warning names a rule that does exist: %q", r.Message)
			}
		case "ok":
			okd = true
		}
		if r.Field != "signatures.disabled_rules" {
			t.Errorf("unexpected field %q", r.Field)
		}
	}
	if !warned {
		t.Errorf("expected a warning for the unknown name, got %+v", results)
	}
	if !okd {
		t.Errorf("expected an ok result for the names that matched, got %+v", results)
	}

	clean := validateDisabledRules(dir, []string{"sample_rule"})
	for _, r := range clean {
		if r.Level == "warn" {
			t.Errorf("a name that matches a loaded rule must not warn: %+v", clean)
		}
	}

	if got := validateDisabledRules(dir, nil); got != nil {
		t.Errorf("no configured names must produce no results, got %+v", got)
	}
}
