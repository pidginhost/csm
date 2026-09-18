package checks

import (
	"strings"
	"testing"
)

func TestPHPCodeOnlyAttributeStrings(t *testing.T) {
	for name, prefix := range map[string]string{
		"single quoted":    "#[Example('?>')] function example() {}\n",
		"double quoted":    "#[Example(\"?>\")] function example() {}\n",
		"block comment":    "#[Example /* ?> */] function example() {}\n",
		"nowdoc":           "#[Example(<<<'TEXT'\n?>\nTEXT)] function example() {}\n",
		"after CR comment": "# comment\r#[Example('?>')] function example() {}\n",
	} {
		t.Run(name, func(t *testing.T) {
			content := "<?php\n" + prefix + "$runner = 'system'; $runner($_GET['cmd']);\n"
			code := phpCodeOnly(content)
			if want := strings.Repeat(" ", len("<?php")) + content[len("<?php"):]; code != want {
				t.Errorf("attribute content changed PHP mode: got %q, want %q", code, want)
			}
			res := analyzePHPString(t, content)
			if !strings.Contains(res.details, "variable function name resolves to decoder or exec primitive") {
				t.Errorf("indirect execution after attribute was missed: %q", res.details)
			}
		})
	}
}

func TestVarFuncAttributeLiterals(t *testing.T) {
	for name, tc := range map[string]struct {
		content string
		want    bool
	}{
		"same line call":             {"#[Example] function example() {} $runner = 'system'; $runner($_GET['cmd']);", true},
		"hash comment":               {"# [Example] function example() {} $runner = 'system'; $runner($_GET['cmd']);", false},
		"quoted example":             {`#[Example('$runner = "system"; $runner($_GET["cmd"]);')] function example() {}`, false},
		"nowdoc example":             {"#[Example(<<<'TEXT'\n$runner = 'system'; $runner($_GET['cmd']);\nTEXT)] function example() {}", false},
		"nowdoc assignment":          {"#[Example(<<<'TEXT'\n$runner = 'system';\nTEXT)] function example() {}\n$runner($_GET['cmd']);", false},
		"nowdoc call":                {"$runner = 'system';\n#[Example(<<<'TEXT'\n$runner($_GET['cmd']);\nTEXT)] function example() {}", false},
		"nowdoc quote before call":   {"#[Example(<<<'TEXT'\nit's documentation\nTEXT)] function example() {}\n$runner = 'system'; $runner($_GET['cmd']);", true},
		"nowdoc reassignment":        {"$runner = 'system';\n#[Example(<<<'TEXT'\n$runner = 'trim';\nTEXT)] function example() {}\n$runner($_GET['cmd']);", true},
		"call after nowdoc close":    {"#[Example(<<<'TEXT'\nit's documentation\nTEXT)] function example() {} $runner = 'system'; $runner($_GET['cmd']);", true},
		"quoted request":             {`$runner = 'system'; #[Example('$_GET')] function example() {} $runner('date');`, false},
		"call after multiline quote": {"#[Example(\"documentation\nexample\")] function example() {} $runner = 'system'; $runner($_GET['cmd']);", true},
		"multiline literal request":  {"$runner = 'system';\n#[Example('documentation\n$_GET')] function example() {} $runner('date');", false},
	} {
		t.Run(name, func(t *testing.T) {
			content := "<?php\n" + tc.content
			if got := detectVarFuncDangerousAssignment(content); got != tc.want {
				t.Errorf("indirect execution = %v, want %v", got, tc.want)
			}
			res := analyzePHPString(t, content)
			if got := strings.Contains(res.details, "variable function name resolves to decoder or exec primitive"); got != tc.want {
				t.Errorf("indirect execution indicator = %v, want %v: %q", got, tc.want, res.details)
			}
		})
	}
}

func TestPHPCodeOnlyAttributeAfterCommentCloseTag(t *testing.T) {
	for _, comment := range []string{"#", "//"} {
		content := "<?php " + comment + " ?> #[Example('text')] function example() {} $runner = 'system'; $runner($_GET['cmd']);"
		code := phpCodeOnly(content)
		if strings.Contains(code, "Example") || strings.Contains(code, "$runner") {
			t.Errorf("page text after %s comment close tag was treated as PHP: %q", comment, code)
		}
	}
}
