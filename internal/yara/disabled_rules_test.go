//go:build yara

package yara

import (
	"os"
	"path/filepath"
	"testing"
)

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
