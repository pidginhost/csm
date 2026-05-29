package checks

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A quote inside a heredoc/nowdoc body must not desync the string scanner. The
// old strip functions only knew '...' and "..." quotes, so an apostrophe in a
// heredoc body opened a phantom string that swallowed the real eval/decode call
// after the heredoc -- hiding a genuine webshell from the structural detectors.
func TestAnalyzePHPContent_EvalAfterHeredocWithQuote(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "h.php")
	content := "<?php\n" +
		"$tpl = <<<EOT\n" +
		"it's a \"templated\" banner line\n" +
		"EOT;\n" +
		"eval(base64_decode($_POST['c']));\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	r := analyzePHPContent(path)
	if r.check == "" {
		t.Fatalf("eval(base64_decode($_POST)) after a heredoc must still be detected; got no finding (details=%q)", r.details)
	}
}

func TestAnalyzePHPContent_EvalAfterHeredocCaseVariantBodyLine(t *testing.T) {
	res := analyzePHPString(t, "<?php\n"+
		"$tpl = <<<EOT\n"+
		"eot;\n"+
		"it's still string body\n"+
		"EOT;\n"+
		"eval(base64_decode($_POST['c']));\n")
	if !strings.Contains(res.details, "eval() directly wrapping encoding/compression function") {
		t.Fatalf("case-variant body line must not close heredoc before post-heredoc eval; details=%q", res.details)
	}
}

func TestAnalyzePHPContent_ContentSignalInsideHeredocStillScanned(t *testing.T) {
	res := analyzePHPString(t, "<?php\n"+
		"$tpl = <<<'EOT'\n"+
		"https://pastebin.com/raw/abc\n"+
		"EOT;\n")
	if !strings.Contains(res.details, "remote payload URL") {
		t.Fatalf("content signals inside heredoc body must still be scanned; details=%q", res.details)
	}
}

// stripPHPStringsFromCode must blank a heredoc body so its contents are not
// analysed as code, and a nowdoc must behave the same.
func TestStripPHPStringsFromCode_BlanksHeredoc(t *testing.T) {
	cases := []struct{ name, code string }{
		{"heredoc", "$a = <<<EOT\nsystem($_GET[c]);\nEOT;\n$b = 1;\n"},
		{"nowdoc", "$a = <<<'EOT'\nsystem($_GET[c]);\nEOT;\n$b = 1;\n"},
		{"indented close (7.3+)", "$a = <<<EOT\n    system($_GET[c]);\n    EOT;\n$b = 1;\n"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := stripPHPStringsFromCode(c.code)
			if containsToken(got, "system") {
				t.Errorf("heredoc body leaked into stripped code: %q", got)
			}
			// Code after the heredoc must survive.
			if !containsToken(got, "$b") {
				t.Errorf("code after heredoc was lost: %q", got)
			}
		})
	}
}

// stripPHPCommentsFromCode must keep a heredoc verbatim (it is string data, not
// a comment) so a '#' or '//' inside the body is not mistaken for a comment.
func TestStripPHPCommentsFromCode_KeepsHeredocBody(t *testing.T) {
	code := "$a = <<<EOT\n# not a comment\nhttp://evil.example/x // also not\nEOT;\n$b = 1;\n"
	got := stripPHPCommentsFromCode(code)
	if !containsToken(got, "evil.example") {
		t.Errorf("heredoc body must survive comment stripping: %q", got)
	}
}

func TestPHPHeredocOpenRejectsNonOpeners(t *testing.T) {
	cases := []string{
		"$x = $a << $b;\n",
		"$x = $a < $b;\n",
		"$x = <<<<EOT\nbody\nEOT;\n",
		"$x = <<<123\nbody\n123;\n",
	}
	for _, code := range cases {
		t.Run(code, func(t *testing.T) {
			for i := 0; i < len(code); i++ {
				if label, _, ok := phpHeredocOpen(code, i); ok {
					t.Fatalf("non-opener at offset %d parsed as heredoc label %q", i, label)
				}
			}
		})
	}
}

func TestPHPHeredocEndRequiresExactCaseSensitiveLabel(t *testing.T) {
	code := "<<<EOT\nEOTHER\neot;\n  EOT;\n$after = 1;\n"
	label, bodyStart, ok := phpHeredocOpen(code, 0)
	if !ok {
		t.Fatal("expected heredoc opener")
	}
	end := phpHeredocEnd(code, bodyStart, label)
	if got := code[end:]; !strings.HasPrefix(got, ";\n$after") {
		t.Fatalf("heredoc closed at wrong label; suffix=%q", got)
	}
}

func TestPHPHeredocEndUnterminatedConsumesEOF(t *testing.T) {
	code := "<<<EOT\nbody\n"
	label, bodyStart, ok := phpHeredocOpen(code, 0)
	if !ok {
		t.Fatal("expected heredoc opener")
	}
	if end := phpHeredocEnd(code, bodyStart, label); end != len(code) {
		t.Fatalf("unterminated heredoc end=%d, want %d", end, len(code))
	}
}

func containsToken(s, tok string) bool {
	return len(s) > 0 && len(tok) > 0 && indexToken(s, tok) >= 0
}

func indexToken(s, tok string) int {
	for i := 0; i+len(tok) <= len(s); i++ {
		if s[i:i+len(tok)] == tok {
			return i
		}
	}
	return -1
}
