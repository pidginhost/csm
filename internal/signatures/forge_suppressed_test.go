package signatures

import (
	"strings"
	"testing"
)

// YARA Forge ships community rules of mixed quality. A rule whose condition is
// satisfied by ordinary code produces findings on every account on the server,
// which buries real detections. Such a rule is dropped at ingest by name, and
// CSM keeps its own tightened rule for the technique instead.

func TestForgeSuppressedRulesIncludesHTMLSmugglingA(t *testing.T) {
	found := false
	for _, name := range forgeSuppressedRules() {
		if name == "ELCEEF_HTML_Smuggling_A" {
			found = true
		}
	}
	if !found {
		t.Error("ELCEEF_HTML_Smuggling_A should be suppressed: its payload-marker count is satisfied by the generic charCodeAt(x)^ idiom, so it fires on minified bundles carrying no smuggled payload")
	}
}

func TestMergeDisabledRulesAppliesBuiltinsWithoutOperatorConfig(t *testing.T) {
	merged := mergeDisabledRules(nil)
	if len(merged) == 0 {
		t.Fatal("built-in suppressions must apply when the operator configured none")
	}
	for _, builtin := range forgeSuppressedRules() {
		if !contains(merged, builtin) {
			t.Errorf("built-in suppression %q missing from merged list", builtin)
		}
	}
}

func TestMergeDisabledRulesKeepsOperatorEntriesAndDeduplicates(t *testing.T) {
	merged := mergeDisabledRules([]string{"Operator_Rule", "ELCEEF_HTML_Smuggling_A"})
	if !contains(merged, "Operator_Rule") {
		t.Error("operator-configured rule must survive the merge")
	}
	seen := map[string]int{}
	for _, name := range merged {
		seen[name]++
	}
	for name, n := range seen {
		if n > 1 {
			t.Errorf("rule %q duplicated %d times in merged list", name, n)
		}
	}
}

// The suppression must actually remove the rule body from downloaded content.
func TestFilterDisabledRulesDropsSuppressedForgeRule(t *testing.T) {
	content := []byte("rule Keep_Me { condition: true }\n" +
		"rule ELCEEF_HTML_Smuggling_A : T1027 FILE\n{\n\tcondition:\n\t\ttrue\n}\n" +
		"rule Keep_Me_Too { condition: true }\n")
	got := string(filterDisabledRules(content, mergeDisabledRules(nil)))
	if strings.Contains(got, "ELCEEF_HTML_Smuggling_A") {
		t.Error("suppressed Forge rule still present after filtering")
	}
	for _, keep := range []string{"Keep_Me", "Keep_Me_Too"} {
		if !strings.Contains(got, keep) {
			t.Errorf("filtering removed unrelated rule %q", keep)
		}
	}
}

func contains(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}

// YARA Forge writes a rule header and its opening brace on separate lines.
// Removing such a rule used to leave its body behind, which made the whole tier
// fail to compile -- so an operator-configured disabled_rules entry silently
// rejected every subsequent Forge update instead of dropping one rule.
func TestFilterDisabledRulesRemovesBodyWhenBraceOnNextLine(t *testing.T) {
	content := []byte("rule Keep_One { condition: true }\n" +
		"rule Drop_Me : T1027 FILE\n{\n\tstrings:\n\t\t$a = \"x\"\n\tcondition:\n\t\t$a\n}\n" +
		"rule Keep_Two { condition: true }\n")
	got := string(filterDisabledRules(content, []string{"Drop_Me"}))
	for _, leftover := range []string{"Drop_Me", "$a", "strings:"} {
		if strings.Contains(got, leftover) {
			t.Errorf("removed rule left %q behind: %q", leftover, got)
		}
	}
	for _, keep := range []string{"Keep_One", "Keep_Two"} {
		if !strings.Contains(got, keep) {
			t.Errorf("filtering removed unrelated rule %q", keep)
		}
	}
}
