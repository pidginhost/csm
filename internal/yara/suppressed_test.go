package yara

import (
	"strings"
	"testing"
)

func TestStripRulesPreservesOtherRules(t *testing.T) {
	for _, tc := range []struct{ name, source, want string }{
		{"exact name", "rule drop_extra { condition: true }\nrule drop { condition: true }\nrule predrop { condition: true }", "rule drop_extra { condition: true }\n\nrule predrop { condition: true }"},
		{"same line", "rule drop { condition: true } rule keep { condition: true }", " rule keep { condition: true }"},
		{"second on line", "rule keep { condition: true } rule drop { condition: true }", "rule keep { condition: true } "},
		{"quoted brace", "rule drop { meta: note = \"{\" condition: true }\nrule keep { condition: true }", "\nrule keep { condition: true }"},
		{"comment brace", "rule drop { /* { */ condition: true }\nrule keep { condition: true }", "\nrule keep { condition: true }"},
		{"regex brace", "rule drop { strings: $a = /[{]/ condition: $a }\nrule keep { condition: true }", "\nrule keep { condition: true }"},
		{"modifiers", "global private\trule\tdrop\n{ condition: true }\nrule keep { condition: true }", "\nrule keep { condition: true }"},
		{"comment declaration", "/*\nrule drop {\n*/\nrule keep { condition: true }", "/*\nrule drop {\n*/\nrule keep { condition: true }"},
		{"incomplete body", "rule drop { condition: true", "rule drop { condition: true"},
		{"incomplete header", "rule drop\nrule keep { condition: true }", "rule drop\nrule keep { condition: true }"},
		{"incomplete tags", "rule drop : tag\nprivate rule keep { condition: true }", "rule drop : tag\nprivate rule keep { condition: true }"},
		{"tagged rule", "private rule drop : first second { condition: true }\nrule keep { condition: true }", "\nrule keep { condition: true }"},
		{"missing name", "rule { condition: true }\nrule keep { condition: true }", "rule { condition: true }\nrule keep { condition: true }"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := string(StripRules([]byte(tc.source), []string{"drop"})); got != tc.want {
				t.Errorf("stripped source = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestStripRulesNormalizesConfiguredNames(t *testing.T) {
	source := "rule Drop { condition: true }\nrule Drop_extra { condition: true }"
	if got := string(StripRules([]byte(source), []string{" DROP "})); got != "\nrule Drop_extra { condition: true }" {
		t.Fatalf("normalized name did not remove exactly one rule: %s", got)
	}
}

func FuzzStripRules(f *testing.F) {
	for _, seed := range []string{"{", "}", `\\\"`, "/* rule drop { */", "/[{}]/", "\nrule drop {"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, text string) {
		// Metadata is arbitrary quoted data, never syntax or another rule.
		text = strings.NewReplacer("\\", "\\\\", "\"", "\\\"", "\n", "\\n", "\r", "\\r").Replace(text)
		source := "rule drop { meta: note = \"" + text + "\" condition: true }\nrule keep { condition: true }"
		if got := string(StripRules([]byte(source), []string{"drop"})); got != "\nrule keep { condition: true }" {
			t.Fatalf("stripping data changed another rule: %q", got)
		}
	})
}
