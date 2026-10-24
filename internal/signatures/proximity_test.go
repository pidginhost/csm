package signatures

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRegexPairProximity(t *testing.T) {
	dir := t.TempDir()
	err := os.WriteFile(filepath.Join(dir, "pairs.yml"), []byte(`rules:
  - name: paired
    file_types: [".php"]
    patterns: ["marker"]
    min_match: 2
    require_regex: true
    regex_pairs:
      - first: '\bread\b'
        second: '\beval\b'
        max_distance: 12
`), 0600)
	if err != nil {
		t.Fatal(err)
	}
	scanner := NewScanner(dir)
	if err := scanner.LoadError(); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, content string
		want          bool
	}{
		{"forward boundary", "marker read        eval", true},
		{"reverse boundary", "marker eval        read", true},
		{"outside boundary", "marker read         eval", false},
		{"later pair", "marker read .................... eval read", true},
		{"repeated first", "marker read .................... read eval", true},
		{"missing first", "marker eval", false},
		{"missing second", "marker read", false},
		{"minimum evidence", "read eval", false},
		{"word boundaries", "marker spread evaluation", false},
		{"case insensitive", "marker READ EVAL", true},
		{"byte offsets", "marker read /*\u754c\u754c*/eval", false},
		{"invalid UTF-8", "marker read \xff eval", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := scanner.ScanContent([]byte(tc.content), ".php")
			if hasRule(got, "paired") != tc.want {
				t.Fatalf("paired = %v, want %v", got, tc.want)
			}
			if tc.want && (len(got) != 1 || len(got[0].Matched) != 2) {
				t.Fatalf("pair must count once: %v", got)
			}
		})
	}
}

func TestRegexPairZeroDistance(t *testing.T) {
	rule := Rule{RegexPairs: []RegexPair{{First: `\bread`, Second: `read\b`}}, MinMatch: 1}
	if err := rule.compile(); err != nil {
		t.Fatal(err)
	}
	scanner := &Scanner{rules: []Rule{rule}}
	for _, tc := range []struct {
		content string
		want    bool
	}{
		{"read", true},
		{"reader bread", false},
	} {
		if got := len(scanner.ScanContent([]byte(tc.content), ".php")) > 0; got != tc.want {
			t.Errorf("%q: got %v, want %v", tc.content, got, tc.want)
		}
	}
}

func TestRegexPairValidation(t *testing.T) {
	for _, pair := range []string{
		"{first: '', second: eval, max_distance: 12}",
		"{first: read, second: '', max_distance: 12}",
		"{first: read, second: eval, max_distance: -1}",
		"{first: '[', second: eval, max_distance: 12}",
		"{first: read, second: '[', max_distance: 12}",
	} {
		t.Run(pair, func(t *testing.T) {
			dir := t.TempDir()
			data := "rules:\n  - name: bad\n    regex_pairs:\n      - " + pair + "\n"
			if err := os.WriteFile(filepath.Join(dir, "pairs.yml"), []byte(data), 0600); err != nil {
				t.Fatal(err)
			}
			if scanner := NewScanner(dir); scanner.LoadError() == nil || scanner.RuleCount() != 0 {
				t.Fatal("invalid regex pair loaded")
			}
		})
	}
}
