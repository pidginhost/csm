//go:build yara

package yara

import "testing"

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
