package signatures

import (
	"os"
	"path/filepath"
	"testing"
)

func scanRepoRules(t *testing.T, sample []byte) map[string]Match {
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
	if err := s.LoadError(); err != nil {
		t.Fatalf("loading repository rules: %v", err)
	}
	target := filepath.Join(t.TempDir(), "sample.php")
	if err := os.WriteFile(target, sample, 0o644); err != nil {
		t.Fatal(err)
	}
	hit := map[string]Match{}
	for _, m := range s.ScanFile(target, 1<<20) {
		hit[m.RuleName] = m
	}
	return hit
}

// eval("?>".base64_decode(...)) is the packer the 2026-07-23 hospitalityculture
// shells used to evade php_eval_decode_chain, which required the decoder
// immediately after eval(.
func TestPHPEvalDecodeChainMatchesPhpCloseConcatPacker(t *testing.T) {
	jfif := append([]byte("\xff\xd8\xff\xe0\x00\x10JFIF\x00"), []byte(
		`<?php eval("?>".base64_decode("Pz48P3BocCBzeXN0ZW0oJF9HRVRbMF0pOw==")); ?>`,
	)...)
	for _, sample := range [][]byte{
		jfif,
		[]byte(`<?= eval('?>' . gzinflate(base64_decode($payload))); ?>`),
	} {
		match, ok := scanRepoRules(t, sample)["php_eval_decode_chain"]
		if !ok {
			t.Errorf("php_eval_decode_chain did not match PHP-close decoder packer: %s", sample)
		}
		if match.Severity != "critical" || match.Category != "dropper" {
			t.Errorf("php_eval_decode_chain metadata = %q/%q, want critical/dropper", match.Severity, match.Category)
		}
	}
}

// A template engine evaluating compiled PHP with a "?>" prefix and no decoder
// is not a packer loader.
func TestPHPEvalDecodeChainIgnoresTemplateEval(t *testing.T) {
	for _, sample := range [][]byte{
		[]byte(`<?php $c = $this->compile($tpl); eval("?>" . $c); ?>`),
		[]byte(`<?php eval("prefix" . base64_decode($payload)); ?>`),
	} {
		if _, ok := scanRepoRules(t, sample)["php_eval_decode_chain"]; ok {
			t.Errorf("php_eval_decode_chain false-positive on non-packer eval: %s", sample)
		}
	}
}

// The nickola/web-console command tool dropped as a shell matched no rule.
func TestWebConsoleToolDetected(t *testing.T) {
	for _, tc := range []struct {
		identity string
		accounts string
	}{
		{"// Web Console v0.9.7 (2016-11-05)\n", "$ACCOUNTS = array();\n"},
		{"// GitHub: https://github.com/nickola/web-console\n", "$ACCOUNTS[$USER] = $PASSWORD;\n"},
	} {
		sample := []byte("<?php\n" + tc.identity +
			"$NO_LOGIN = false;\n$USER = 'Noxipom12';\n$PASSWORD = 'x';\n" +
			tc.accounts +
			"$p = proc_open($command, $descriptors, $pipes, $cwd);\n")
		match, ok := scanRepoRules(t, sample)["webshell_web_console"]
		if !ok {
			t.Errorf("webshell_web_console did not match tool identity %q", tc.identity)
		}
		if match.Severity != "critical" || match.Category != "webshell" {
			t.Errorf("webshell_web_console metadata = %q/%q, want critical/webshell", match.Severity, match.Category)
		}
	}
}

func TestWebConsoleRequiresEveryStructuralMarker(t *testing.T) {
	for _, tc := range []struct {
		name   string
		sample string
	}{
		{
			name: "identity",
			sample: "<?php\n$NO_LOGIN = false;\n$ACCOUNTS = array();\n" +
				"$p = proc_open($command, $descriptors, $pipes);\n",
		},
		{
			name: "no-login setting",
			sample: "<?php\n// Web Console v0.9.7\n$ACCOUNTS = array();\n" +
				"$p = proc_open($command, $descriptors, $pipes);\n",
		},
		{
			name: "accounts setting",
			sample: "<?php\n// Web Console v0.9.7\n$NO_LOGIN = false;\n" +
				"$p = proc_open($command, $descriptors, $pipes);\n",
		},
		{
			name:   "command sink",
			sample: "<?php\n// Web Console v0.9.7\n$NO_LOGIN = false;\n$ACCOUNTS = array();\n",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, ok := scanRepoRules(t, []byte(tc.sample))["webshell_web_console"]; ok {
				t.Errorf("webshell_web_console matched without %s", tc.name)
			}
		})
	}
}

func TestWebConsoleSystemSinkUsesWordBoundary(t *testing.T) {
	prefix := "<?php\n// Web Console v0.9.7\n$NO_LOGIN = false;\n$ACCOUNTS = array();\n"
	if _, ok := scanRepoRules(t, []byte(prefix+"system($command);\n"))["webshell_web_console"]; !ok {
		t.Error("webshell_web_console did not match the system() sink")
	}
	for _, call := range []string{"filesystem($path);", "ecosystem($path);"} {
		if _, ok := scanRepoRules(t, []byte(prefix+call))["webshell_web_console"]; ok {
			t.Errorf("webshell_web_console treated %s as system()", call)
		}
	}
}
