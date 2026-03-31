package signatures

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRequireRegex(t *testing.T) {
	dir := t.TempDir()
	rulesYAML := `
version: 1
rules:
  - name: test_require_regex
    description: "Test rule with require_regex"
    severity: critical
    category: exploit
    file_types: [".php"]
    patterns: ["Plugin Name:", "register_activation_hook"]
    regexes: ["file_put_contents\\s*\\(.*\\.php.*(?:base64_decode|eval)"]
    min_match: 2
    require_regex: true

  - name: test_no_require_regex
    description: "Test rule without require_regex"
    severity: critical
    category: exploit
    file_types: [".php"]
    patterns: ["Plugin Name:", "register_activation_hook"]
    regexes: ["file_put_contents\\s*\\(.*\\.php.*(?:base64_decode|eval)"]
    min_match: 2
    require_regex: false
`
	if err := os.WriteFile(filepath.Join(dir, "test.yml"), []byte(rulesYAML), 0644); err != nil {
		t.Fatal(err)
	}

	scanner := NewScanner(dir)
	if scanner.RuleCount() != 2 {
		t.Fatalf("expected 2 rules, got %d", scanner.RuleCount())
	}

	// Legitimate plugin: has patterns but NOT the malicious regex
	legitimate := []byte(`<?php
/*
Plugin Name: Akismet Anti-spam
*/
register_activation_hook(__FILE__, 'activate');
function activate() { update_option('akismet_activated', true); }
`)

	// Malicious plugin: has patterns AND the malicious regex
	malicious := []byte(`<?php
/*
Plugin Name: Fake Security Plugin
*/
register_activation_hook(__FILE__, 'drop_shell');
function drop_shell() { file_put_contents(__DIR__.'/shell.php', base64_decode($payload)); }
`)

	// Legitimate file: require_regex rule should NOT match, non-require should match
	matches := scanner.ScanContent(legitimate, ".php")
	for _, m := range matches {
		if m.RuleName == "test_require_regex" {
			t.Error("require_regex rule should NOT match legitimate plugin (only patterns matched, no regex)")
		}
		if m.RuleName == "test_no_require_regex" { //nolint:staticcheck // expected match, handled below
			continue
		}
	}

	// Verify the non-require rule DID match the legitimate file (confirming the FP scenario)
	foundNonRequire := false
	for _, m := range matches {
		if m.RuleName == "test_no_require_regex" {
			foundNonRequire = true
		}
	}
	if !foundNonRequire {
		t.Error("non-require_regex rule should match legitimate plugin (demonstrates the false positive)")
	}

	// Malicious file: BOTH rules should match
	matches = scanner.ScanContent(malicious, ".php")
	foundRequire := false
	foundNonRequire = false
	for _, m := range matches {
		if m.RuleName == "test_require_regex" {
			foundRequire = true
		}
		if m.RuleName == "test_no_require_regex" {
			foundNonRequire = true
		}
	}
	if !foundRequire {
		t.Error("require_regex rule should match malicious plugin (patterns + regex both matched)")
	}
	if !foundNonRequire {
		t.Error("non-require_regex rule should match malicious plugin")
	}
}

func TestRequireRegexNoRegexesDefined(t *testing.T) {
	dir := t.TempDir()
	rulesYAML := `
version: 1
rules:
  - name: test_patterns_only
    description: "Rule with require_regex but no regexes defined"
    severity: high
    category: webshell
    file_types: [".php"]
    patterns: ["eval(", "base64_decode"]
    min_match: 2
    require_regex: true
`
	if err := os.WriteFile(filepath.Join(dir, "test.yml"), []byte(rulesYAML), 0644); err != nil {
		t.Fatal(err)
	}

	scanner := NewScanner(dir)

	content := []byte(`<?php eval(base64_decode($x)); ?>`)
	matches := scanner.ScanContent(content, ".php")

	// require_regex is true but no regexes defined — rule should never match
	// This is a misconfigured rule, but we don't want it silently matching everything
	for _, m := range matches {
		if m.RuleName == "test_patterns_only" {
			t.Error("rule with require_regex=true but no regexes should not match")
		}
	}
}

func TestScanContentBasic(t *testing.T) {
	dir := t.TempDir()
	rulesYAML := `
version: 1
rules:
  - name: simple_webshell
    description: "Simple webshell"
    severity: critical
    category: webshell
    file_types: [".php"]
    patterns: ["eval(", "base64_decode"]
    min_match: 2
`
	if err := os.WriteFile(filepath.Join(dir, "test.yml"), []byte(rulesYAML), 0644); err != nil {
		t.Fatal(err)
	}

	scanner := NewScanner(dir)

	// Should match
	matches := scanner.ScanContent([]byte(`<?php eval(base64_decode("abc")); ?>`), ".php")
	if len(matches) != 1 {
		t.Errorf("expected 1 match, got %d", len(matches))
	}

	// Should not match (only 1 pattern)
	matches = scanner.ScanContent([]byte(`<?php eval("hello"); ?>`), ".php")
	if len(matches) != 0 {
		t.Errorf("expected 0 matches, got %d", len(matches))
	}

	// Wrong extension
	matches = scanner.ScanContent([]byte(`<?php eval(base64_decode("abc")); ?>`), ".html")
	if len(matches) != 0 {
		t.Errorf("expected 0 matches for .html, got %d", len(matches))
	}
}

func TestExcludePatterns(t *testing.T) {
	dir := t.TempDir()
	rulesYAML := `
version: 1
rules:
  - name: excluded_rule
    description: "Rule with exclusion"
    severity: high
    category: webshell
    file_types: [".php"]
    patterns: ["eval("]
    exclude_patterns: ["WordPress"]
    min_match: 1
`
	if err := os.WriteFile(filepath.Join(dir, "test.yml"), []byte(rulesYAML), 0644); err != nil {
		t.Fatal(err)
	}

	scanner := NewScanner(dir)

	// Should be excluded
	matches := scanner.ScanContent([]byte(`<?php /* WordPress core */ eval($x); ?>`), ".php")
	if len(matches) != 0 {
		t.Errorf("expected exclusion to suppress match, got %d", len(matches))
	}

	// Should match (no exclusion trigger)
	matches = scanner.ScanContent([]byte(`<?php eval($x); ?>`), ".php")
	if len(matches) != 1 {
		t.Errorf("expected 1 match without exclusion, got %d", len(matches))
	}
}
