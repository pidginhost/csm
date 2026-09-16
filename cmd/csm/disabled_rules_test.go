package main

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestValidateDisabledRulesRecognizesUncompilableRule(t *testing.T) {
	dir := t.TempDir()
	data := "rules:\n  - name: broken\n    regexes: ['[']\n  - name: keep\n    patterns: [needle]\n"
	if err := os.WriteFile(filepath.Join(dir, "rules.yml"), []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	results := validateDisabledRules(dir, []string{"broken", " BROKEN "})
	if len(results) != 1 || results[0].Level != "ok" || results[0].Message != "1 rule(s) disabled" {
		t.Fatalf("disabled invalid regex should be recognized once: %+v", results)
	}
}

func TestValidateDisabledRulesWithoutReadableRules(t *testing.T) {
	for _, contents := range []string{"", "rules: ["} {
		dir := t.TempDir()
		if contents != "" {
			if err := os.WriteFile(filepath.Join(dir, "rules.yml"), []byte(contents), 0600); err != nil {
				t.Fatal(err)
			}
		}
		results := validateDisabledRules(dir, []string{"unknown"})
		if len(results) != 1 || results[0].Level != "warn" || !strings.Contains(results[0].Message, "unknown") {
			t.Fatalf("unreadable rules should not validate a name: %+v", results)
		}
	}
}

func TestDisabledRuleValidationUsesSourceDeclarations(t *testing.T) {
	dir := t.TempDir()
	source := "/*\nrule fake { condition: true }\n*/\nglobal private\trule\tactual { condition: true } rule next { condition: true }"
	if err := os.WriteFile(filepath.Join(dir, "rules.yar"), []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	if got := yaraRuleNamesIn(dir); !reflect.DeepEqual(got, []string{"actual", "next"}) {
		t.Fatalf("known names = %v, want actual and next", got)
	}
}

func TestDisabledRuleValidationAcceptsMixedCaseExtension(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "rules.YARA"), []byte("rule actual { condition: true }"), 0600); err != nil {
		t.Fatal(err)
	}
	if got := yaraRuleNamesIn(dir); !reflect.DeepEqual(got, []string{"actual"}) {
		t.Fatalf("known names = %v, want actual", got)
	}
}

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
