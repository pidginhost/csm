package signatures

import "testing"

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
