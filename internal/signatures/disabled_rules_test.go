package signatures

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDisabledRulesCanEmptyRuleset(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rules.yml")
	write := func(rules string) {
		t.Helper()
		if err := os.WriteFile(path, []byte("version: 1\nrules:\n"+rules), 0600); err != nil {
			t.Fatal(err)
		}
	}
	disabled := "  - name: drop\n    patterns: [needle]\n"
	write(disabled)
	s := NewScanner(dir, "drop")
	if err := s.LoadError(); err != nil {
		t.Errorf("intentionally empty ruleset failed to load: %v", err)
	}
	if s.DisabledRuleCount() != 1 || len(s.DisabledRulesWithoutMatch()) != 0 {
		t.Errorf("disabled rule was not accounted for: count=%d, unmatched=%v", s.DisabledRuleCount(), s.DisabledRulesWithoutMatch())
	}
	write(disabled + "  - name: keep\n    patterns: [needle]\n")
	if err := s.Reload(); err != nil {
		t.Fatal(err)
	}
	if got := s.ScanContent([]byte("needle"), ".php"); len(got) != 1 || got[0].RuleName != "keep" {
		t.Fatalf("control scan = %v, want keep", got)
	}
	write(disabled + "  - name: broken\n    regexes: ['[']\n")
	if err := s.Reload(); err == nil {
		t.Fatal("a disabled rule hid an enabled rule's compilation failure")
	}
	if got := s.ScanContent([]byte("needle"), ".php"); len(got) != 1 || got[0].RuleName != "keep" {
		t.Fatalf("failed reload lost the last working ruleset: %v", got)
	}
	write(disabled)
	if err := s.Reload(); err != nil {
		t.Errorf("intentionally empty reload failed: %v", err)
	}
	if got := s.ScanContent([]byte("needle"), ".php"); len(got) != 0 || s.RuleCount() != 0 {
		t.Errorf("empty reload retained stale rules: %v", got)
	}
	if s.LoadError() != nil || s.DisabledRuleCount() != 1 {
		t.Errorf("successful empty reload did not clear the failure: %v", s.LoadError())
	}
}

// Operators reach for signatures.disabled_rules when a shipped rule misfires
// on production. Before this, the setting only filtered YARA-Forge downloads:
// naming a rule from malware.yml there changed nothing and said nothing.

func TestDisabledRuleIsNotLoaded(t *testing.T) {
	enabled := NewScanner("../../configs")
	if enabled.RuleCount() == 0 {
		t.Fatal("expected repository rules to load")
	}
	sample := []byte(`<?php eval(base64_decode($_POST['x']));`)
	var target string
	for _, m := range enabled.ScanContent(sample, ".php") {
		target = m.RuleName
		break
	}
	if target == "" {
		t.Fatal("expected the sample to match at least one rule")
	}

	disabled := NewScanner("../../configs", target)
	if disabled.RuleCount() >= enabled.RuleCount() {
		t.Errorf("disabled rule still loaded: %d rules with %q disabled, %d without",
			disabled.RuleCount(), target, enabled.RuleCount())
	}
	for _, m := range disabled.ScanContent(sample, ".php") {
		if m.RuleName == target {
			t.Errorf("rule %q matched although it is disabled", target)
		}
	}
}

func TestDisabledRulesWithoutMatchReportsUnknownNames(t *testing.T) {
	s := NewScanner("../../configs", "php_goto_obfuscation", "no_such_rule_name")
	unmatched := s.DisabledRulesWithoutMatch()
	if len(unmatched) != 1 || unmatched[0] != "no_such_rule_name" {
		t.Errorf("unmatched disabled names = %v, want [no_such_rule_name]", unmatched)
	}
}
