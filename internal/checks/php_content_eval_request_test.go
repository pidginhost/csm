package checks

import (
	"os"
	"path/filepath"
	"testing"
)

// Three eval shapes the analyzer did not read: eval() of request input with
// no decoder at all (the simplest possible shell), a string literal
// concatenated before the decoder (`eval("?>" . base64_decode(...))`, the
// stock way to drop out of PHP mode), and decoders outside the original
// short list. Each is paired with the same second signal the neighbouring
// tests use so the >=2 escalation gate is exercised the same way.
func TestAnalyzePHPContentEvalOfRequestInputAndPrefixedDecoders(t *testing.T) {
	cases := []struct {
		name    string
		content string
	}{
		{
			name: "eval_of_post_input",
			content: "<?php\n" +
				"$u = 'https://pastebin.com/raw/abc';\n" +
				"ev" + "al($_POST['c']);\n",
		},
		{
			name: "assert_of_request_input",
			content: "<?php\n" +
				"$u = 'https://pastebin.com/raw/abc';\n" +
				"assert($_REQUEST[\"x\"]);\n",
		},
		{
			name: "eval_string_prefix_before_decoder",
			content: "<?php\n" +
				"$u = 'https://pastebin.com/raw/abc';\n" +
				"ev" + "al(\"?>\" . base64_decode($x));\n",
		},
		{
			name: "eval_hex2bin_decoder",
			content: "<?php\n" +
				"$u = 'https://pastebin.com/raw/abc';\n" +
				"ev" + "al(hex2bin($x));\n",
		},
		{
			name: "eval_strrev_decoder",
			content: "<?php\n" +
				"$u = 'https://pastebin.com/raw/abc';\n" +
				"ev" + "al(strrev($x));\n",
		},
		{
			name: "eval_urldecode_decoder",
			content: "<?php\n" +
				"$u = 'https://pastebin.com/raw/abc';\n" +
				"ev" + "al(urldecode($x));\n",
		},
		{
			name: "eval_convert_uudecode_decoder",
			content: "<?php\n" +
				"$u = 'https://pastebin.com/raw/abc';\n" +
				"ev" + "al(convert_uudecode($x));\n",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), c.name+".php")
			if err := os.WriteFile(path, []byte(c.content), 0o644); err != nil {
				t.Fatal(err)
			}
			result := analyzePHPContent(path)
			if result.check != "obfuscated_php" {
				t.Errorf("payload should escalate; got check=%q details=%q", result.check, result.details)
			}
		})
	}
}

// eval of a local variable or constant expression must not trip the new
// request-input indicator: template engines and config loaders do that.
func TestAnalyzePHPContentEvalOfLocalVariableNotRequestInput(t *testing.T) {
	content := "<?php\n" +
		"$tpl = file_get_contents(__DIR__ . '/tpl.php');\n" +
		"ev" + "al('?>' . $tpl);\n"
	path := filepath.Join(t.TempDir(), "tpl_loader.php")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	result := analyzePHPContent(path)
	if result.check == "obfuscated_php" {
		t.Errorf("template loader escalated as obfuscated: %q", result.details)
	}
}
