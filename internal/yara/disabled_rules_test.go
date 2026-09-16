//go:build yara

package yara

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDisabledRulesCanEmptyRuleset(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rules.yar")
	write := func(source string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(source), 0600); err != nil {
			t.Fatal(err)
		}
	}
	const disabled = "rule drop { condition: true }"
	write(disabled)
	if _, err := NewScanner(dir, "drop"); err != nil {
		t.Errorf("intentionally empty ruleset failed to load: %v", err)
	}
	write(disabled + " rule keep { condition: true }")
	s, err := NewScanner(dir, "drop")
	if err != nil {
		t.Fatal(err)
	}
	if got := s.ScanBytes([]byte("needle")); len(got) != 1 || got[0].RuleName != "keep" {
		t.Fatalf("control scan = %v, want keep", got)
	}
	write(disabled + " rule broken { condition:")
	if err := s.Reload(); err == nil {
		t.Fatal("a disabled rule hid an enabled rule's compilation failure")
	}
	if got := s.ScanBytes([]byte("needle")); len(got) != 1 || got[0].RuleName != "keep" {
		t.Fatalf("failed reload lost the last working ruleset: %v", got)
	}
	write(disabled)
	if err := s.Reload(); err != nil {
		t.Errorf("intentionally empty reload failed: %v", err)
	}
	if got := s.ScanBytes([]byte("needle")); len(got) != 0 || s.RuleCount() != 0 {
		t.Errorf("empty reload retained stale rules: %v", got)
	}
	if s.DisabledRuleCount() != 1 {
		t.Errorf("disabled count = %d, want 1", s.DisabledRuleCount())
	}
}

func TestDisabledRulePreservesCompiledNeighbors(t *testing.T) {
	dir := t.TempDir()
	source := `global private rule drop {
    strings:
        $a = /[{]/
        $b = "escaped quote: \" {"
        $c = { 01 02 [2-4] 03 }
    condition: any of them
} rule drop_extra { condition: true }
rule predrop { condition: true }`
	if err := os.WriteFile(filepath.Join(dir, "rules.yar"), []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	s, err := NewScanner(dir, " DROP ")
	if err != nil {
		t.Fatal(err)
	}
	for _, reload := range []bool{false, true} {
		if reload {
			if err := s.Reload(); err != nil {
				t.Fatal(err)
			}
		}
		matches, err := s.ScanBytesChecked([]byte("probe"))
		if err != nil {
			t.Fatal(err)
		}
		if s.RuleCount() != 2 || len(matches) != 2 {
			t.Fatalf("reload=%t: got %d rules and %v matches, want both neighbors", reload, s.RuleCount(), matches)
		}
		for _, match := range matches {
			if match.RuleName != "drop_extra" && match.RuleName != "predrop" {
				t.Fatalf("unexpected rule: %s", match.RuleName)
			}
		}
	}
}

// The operator setting that filters YARA-Forge downloads has to reach the
// rules CSM ships too, or switching off a misfiring signature means editing
// rule files on a production host.
func TestDisabledRuleIsNotCompiled(t *testing.T) {
	enabled, err := NewScanner("../../configs")
	if err != nil {
		t.Fatal(err)
	}
	sample := []byte(`<?php eval(base64_decode($_POST['x']));`)
	matches := enabled.ScanBytes(sample)
	if len(matches) == 0 {
		t.Fatal("expected the sample to match at least one rule")
	}
	target := matches[0].RuleName

	disabled, err := NewScanner("../../configs", target)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range disabled.ScanBytes(sample) {
		if m.RuleName == target {
			t.Errorf("rule %q matched although it is disabled", target)
		}
	}
	if disabled.RuleCount() >= enabled.RuleCount() {
		t.Errorf("disabled rule still compiled: %d rules with %q off, %d without",
			disabled.RuleCount(), target, enabled.RuleCount())
	}
}
