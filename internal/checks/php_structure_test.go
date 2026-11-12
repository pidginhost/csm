package checks

import (
	"strings"
	"testing"
)

func TestPHPRequestFlowStructureLiteralBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name    string
		literal string
		keep    bool
	}{
		{"single quotes", `'php://input'`, true},
		{"double quotes", `"php://input"`, true},
		{"mixed case", `'pHp://InPuT'`, true},
		{"longer value", `'php://input_example'`, false},
		{"leading text", `'read php://input'`, false},
		{"trailing space", `'php://input '`, false},
		{"escaped spelling", `"php:\x2f\x2finput"`, false},
		{"escaped backslash", `'php://input\\'`, false},
		{"interpolated spelling", `"php://in${part}"`, false},
		{"nested interpolation", `"{$values["php://input"]}"`, false},
		{"backtick value", "`php://input`", false},
		{"backtick quoted value", "`printf 'php://input'`", false},
		{"backtick quoted example", "`printf \"system(file_get_contents('php://input'))\"`", false},
		{"backtick unmatched quote", "`printf '\nphp://input`", false},
		{"multiline literal", "\"example\r\n'php://input'\r\n\"", false},
		{"UTF-8 literal", "\"\u0130\u212a php://input\"", false},
		{"heredoc", "<<<TEXT\n'php://input'\nTEXT", false},
		{"quoted heredoc", "<<<\"TEXT\"\r\n'php://input'\r\nTEXT", false},
		{"nowdoc", "<<<'TEXT'\n\"php://input\"\nTEXT", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			source := "<?php $body = " + tc.literal + ";\r\nsystem($body);"
			literal := blankPHPStructureTestText(tc.literal)
			if tc.keep {
				literal = tc.literal
			}
			want := "      $body = " + literal + ";\r\nsystem($body);"
			if got := PHPRequestFlowStructure(source); got != want {
				t.Fatalf("structure = %q, want %q", got, want)
			}
		})
	}
}

func TestPHPRequestFlowStructureInertRegions(t *testing.T) {
	for _, region := range []string{
		"// 'php://input'\r\n",
		"# \"php://input\"\n",
		"/* system(file_get_contents('php://input')); */",
	} {
		source := "<?php " + region + "system($local);"
		want := "      " + blankPHPStructureTestText(region) + "system($local);"
		if got := PHPRequestFlowStructure(source); got != want {
			t.Errorf("structure = %q, want %q", got, want)
		}
	}
	const html = "<p>system(file_get_contents('php://input'))</p>\r\n"
	if got, want := PHPRequestFlowStructure(html+"<?php system($local);"), blankPHPStructureTestText(html)+"      system($local);"; got != want {
		t.Errorf("inline HTML structure = %q, want %q", got, want)
	}
}

func TestPHPRequestFlowStructureLiteralAtEOF(t *testing.T) {
	for _, literal := range []string{
		`'php://input'`, `"php://input"`,
		`'php://input`, `"php://input`, `'php://input\'`,
		"`'php://input'", "<<<TEXT\n'php://input'",
		"<<<'TEXT'\n'php://input'", `"{$values["php://input"]}`,
	} {
		want := blankPHPStructureTestText(literal)
		if literal == `'php://input'` || literal == `"php://input"` {
			want = literal
		}
		if got := PHPRequestFlowStructure("<?php " + literal); got != "      "+want {
			t.Errorf("structure = %q, want %q", got, "      "+want)
		}
	}
}

func blankPHPStructureTestText(text string) string {
	var b strings.Builder
	for i := 0; i < len(text); i++ {
		if text[i] == '\r' || text[i] == '\n' {
			b.WriteByte(text[i])
		} else {
			b.WriteByte(' ')
		}
	}
	return b.String()
}
