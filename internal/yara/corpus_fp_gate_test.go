//go:build yara

package yara_test

import (
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"testing"

	csmyara "github.com/pidginhost/csm/internal/yara"
)

// minCorpusFiles is the floor the corpus walk must clear before its result
// means anything. A typo'd or emptied YARA_FP_CORPUS walks nothing, and a gate
// that passes having scanned nothing is worse than no gate at all.
const minCorpusFiles = 5000

// corpusBaseline records rules known to fire on clean third-party code, with
// the observed hit count. Measured 2026-08-20 over 16,074 files of unpacked
// WordPress core and popular plugins: the shipped rule set fires on NONE of
// them, so the baseline is empty and must stay that way.
//
// Adding an entry here is an admission that a rule matches clean vendor code.
// It needs a comment naming the file family it hits and why the rule cannot be
// tightened instead. Never add a path or filename exclusion to the rule to
// avoid an entry.
var corpusBaseline = map[string]int{}

// TestRepositoryRulesAgainstCleanCorpus is the standing guard against the
// false-positive floods that scope widening has caused twice. Point
// YARA_FP_CORPUS at a tree of unpacked WordPress core and plugins:
//
//	YARA_FP_CORPUS=/path/to/corpus go test -tags yara ./internal/yara/ -run TestRepositoryRulesAgainstCleanCorpus -v
func TestRepositoryRulesAgainstCleanCorpus(t *testing.T) {
	root := os.Getenv("YARA_FP_CORPUS")
	if root == "" {
		t.Skip("YARA_FP_CORPUS not set")
	}

	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	configsDir := filepath.Join(filepath.Dir(thisFile), "..", "..", "configs")
	scanner, err := csmyara.NewScanner(configsDir)
	if err != nil {
		t.Fatalf("loading YARA rules: %v", err)
	}
	if scanner.RuleCount() == 0 {
		t.Fatal("scanner loaded zero rules")
	}

	hits := make(map[string]int)
	examples := make(map[string]string)
	scanned := 0
	walkErr := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info == nil || !info.Mode().IsRegular() {
			return nil //nolint:nilerr // an unreadable entry is not a rule failure
		}
		if info.Size() == 0 || info.Size() > 16*1024*1024 {
			return nil
		}
		data, readErr := os.ReadFile(path) // #nosec G304 -- operator-supplied corpus path
		if readErr != nil {
			return nil //nolint:nilerr // see above
		}
		scanned++
		for _, m := range scanner.ScanBytes(data) {
			hits[m.RuleName]++
			if _, seen := examples[m.RuleName]; !seen {
				examples[m.RuleName] = path
			}
		}
		return nil
	})
	if walkErr != nil {
		t.Fatalf("walking corpus: %v", walkErr)
	}
	if scanned < minCorpusFiles {
		t.Fatalf("corpus walked %d files, below the %d floor -- check YARA_FP_CORPUS", scanned, minCorpusFiles)
	}

	var regressions []string
	for name, count := range hits {
		if count > corpusBaseline[name] {
			regressions = append(regressions, name)
		}
	}
	sort.Strings(regressions)
	for _, name := range regressions {
		t.Errorf("rule %s fired %d times on clean third-party code (baseline %d), first at %s",
			name, hits[name], corpusBaseline[name], examples[name])
	}
	t.Logf("scanned %d files with %d rules; %d rules fired", scanned, scanner.RuleCount(), len(hits))
}
