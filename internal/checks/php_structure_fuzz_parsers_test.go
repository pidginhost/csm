package checks

import (
	"strings"
	"testing"
)

func FuzzPHPRequestFlowStructure(f *testing.F) {
	for _, source := range []string{
		"",
		"<?php system(file_get_contents('php://input'));",
		"<?php $x = `cat <<'TEXT'\nsystem(file_get_contents(\"php://input\"))\nTEXT`;",
		"<?php $x = `printf '\n`; system(file_get_contents('php://input'));",
		"<?php $x = \"{$values[\"php://input\"]}\";",
		"<?php $x = <<<'TEXT'\n'php://input'\nTEXT;",
		"<?php /* 'php://input' */ ?>\r\n<p>'php://input'</p>",
		"<?php 'php://input\\'",
		"<?php \"\u0130\u212a\";\r\nnamespace Example { system($value); }",
	} {
		f.Add(source)
	}
	quoteBacktick := strings.NewReplacer("\\", "\\\\", "`", "\\`", "$", "\\$")
	f.Fuzz(func(t *testing.T, source string) {
		if len(source) > 1<<16 {
			return
		}
		executable := PHPExecutableCode(source)
		structure := PHPRequestFlowStructure(source)
		if len(structure) != len(source) || len(executable) != len(source) {
			t.Fatalf("offset drift: source=%d executable=%d structure=%d", len(source), len(executable), len(structure))
		}
		for i := range len(source) {
			if source[i] == '\r' || source[i] == '\n' {
				if structure[i] != source[i] {
					t.Fatalf("line break changed at byte %d", i)
				}
			}
			if structure[i] != executable[i] && structure[i] != ' ' {
				t.Fatalf("nonblank replacement at byte %d", i)
			}
		}

		// Even arbitrary shell text stays opaque, while the following PHP
		// retains its offsets and its complete request-body literal.
		literal := "`" + quoteBacktick.Replace(source) + "`"
		const suffix = "; system(file_get_contents('php://input'));"
		want := "      $x = " + blankPHPStructureTestText(literal) + suffix
		if got := PHPRequestFlowStructure("<?php $x = " + literal + suffix); got != want {
			t.Fatalf("backtick structure = %q, want %q", got, want)
		}
	})
}
