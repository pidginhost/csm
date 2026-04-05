package signatures

import (
	"strings"
	"testing"
)

func TestExtractRuleName(t *testing.T) {
	tests := []struct {
		line string
		want string
	}{
		{"rule SUSP_XOR_Encoded {", "SUSP_XOR_Encoded"},
		{"private rule PRIV_Helper {", "PRIV_Helper"},
		{"rule Webshell_PHP : webshell {", "Webshell_PHP"},
		{"rule NoOpenBrace", "NoOpenBrace"},
		{"not a rule", ""},
		{"", ""},
		{"ruler of the world", ""},
	}
	for _, tt := range tests {
		got := extractRuleName(tt.line)
		if got != tt.want {
			t.Errorf("extractRuleName(%q) = %q, want %q", tt.line, got, tt.want)
		}
	}
}

func TestFilterDisabledRules(t *testing.T) {
	input := []byte("// header comment\nrule Keep_This {\n    strings:\n        $a = \"safe\"\n    condition:\n        $a\n}\n\nrule Remove_Me {\n    strings:\n        $b = \"bad\"\n    condition:\n        $b\n}\n\nrule Also_Keep {\n    condition:\n        true\n}\n")
	disabled := []string{"Remove_Me"}
	result := filterDisabledRules(input, disabled)
	resultStr := string(result)

	if !strings.Contains(resultStr, "Keep_This") {
		t.Error("Keep_This should be preserved")
	}
	if strings.Contains(resultStr, "Remove_Me") {
		t.Error("Remove_Me should be filtered out")
	}
	if !strings.Contains(resultStr, "Also_Keep") {
		t.Error("Also_Keep should be preserved")
	}
}

func TestFilterDisabledRulesPrivate(t *testing.T) {
	input := []byte("private rule Helper {\n    condition:\n        true\n}\n\nrule Main_Rule {\n    condition:\n        Helper\n}\n")
	disabled := []string{"Helper"}
	result := filterDisabledRules(input, disabled)
	resultStr := string(result)

	if strings.Contains(resultStr, "private rule Helper") {
		t.Error("private rule Helper declaration should be filtered out")
	}
	if !strings.Contains(resultStr, "Main_Rule") {
		t.Error("Main_Rule should be preserved")
	}
}

func TestFilterDisabledRulesEmpty(t *testing.T) {
	input := []byte("rule Foo { condition: true }")
	result := filterDisabledRules(input, nil)
	if string(result) != string(input) {
		t.Error("empty disabled list should return input unchanged")
	}
}

func TestCountRules(t *testing.T) {
	input := []byte("rule A { condition: true }\nrule B { condition: true }\nprivate rule C { condition: true }\n// not a rule\n")
	got := countRules(input)
	if got != 3 {
		t.Errorf("countRules() = %d, want 3", got)
	}
}
