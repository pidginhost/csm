package signatures

import (
	"os"
	"path/filepath"
	"testing"
)

func scanRepoRules(t *testing.T, sample []byte) map[string]bool {
	t.Helper()
	rules, err := os.ReadFile(filepath.Join("..", "..", "configs", "malware.yml"))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "malware.yml"), rules, 0o644); err != nil {
		t.Fatal(err)
	}
	s := NewScanner(dir)
	target := filepath.Join(t.TempDir(), "sample.php")
	if err := os.WriteFile(target, sample, 0o644); err != nil {
		t.Fatal(err)
	}
	hit := map[string]bool{}
	for _, m := range s.ScanFile(target, 1<<20) {
		hit[m.RuleName] = true
	}
	return hit
}

// eval("?>".base64_decode(...)) is the packer the 2026-07-23 hospitalityculture
// shells used to evade php_eval_decode_chain, which required the decoder
// immediately after eval(.
func TestPHPEvalDecodeChainMatchesPhpCloseConcatPacker(t *testing.T) {
	hit := scanRepoRules(t, []byte(`<?php eval("?>".base64_decode("Pz48P3BocCBzeXN0ZW0oJF9HRVRbMF0pOw==")); ?>`))
	if !hit["php_eval_decode_chain"] {
		t.Error("php_eval_decode_chain did not match eval(\"?>\".base64_decode(...))")
	}
}

// A template engine evaluating compiled PHP with a "?>" prefix and no decoder
// is not a packer loader.
func TestPHPEvalDecodeChainIgnoresTemplateEval(t *testing.T) {
	hit := scanRepoRules(t, []byte(`<?php $c = $this->compile($tpl); eval("?>" . $c); ?>`))
	if hit["php_eval_decode_chain"] {
		t.Error("php_eval_decode_chain false-positive on template eval with no decoder")
	}
}

// The nickola/web-console command tool dropped as a shell matched no rule.
func TestWebConsoleToolDetected(t *testing.T) {
	sample := []byte("<?php\n// Web Console v0.9.7\n// GitHub: https://github.com/nickola/web-console\n" +
		"$NO_LOGIN = false;\n$USER = 'Noxipom12';\n$ACCOUNTS = array();\n$ACCOUNTS[$USER] = 'x';\n" +
		"$p = proc_open($command, $descriptors, $pipes, $cwd);\n")
	hit := scanRepoRules(t, sample)
	if !hit["webshell_web_console"] {
		t.Error("webshell_web_console did not match nickola web-console tool")
	}
}

func TestWebConsoleProseIgnored(t *testing.T) {
	hit := scanRepoRules(t, []byte(`<?php /* open the Web Console tab for logs */ echo "Web Console"; ?>`))
	if hit["webshell_web_console"] {
		t.Error("webshell_web_console false-positive on prose mention")
	}
}
