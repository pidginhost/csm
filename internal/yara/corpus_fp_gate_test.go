//go:build yara

package yara_test

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"testing"

	"github.com/pidginhost/csm/internal/contenttype"
	csmyara "github.com/pidginhost/csm/internal/yara"
)

// minCorpusFiles is the floor the corpus walk must clear before its result
// means anything. A typo'd or emptied YARA_FP_CORPUS walks nothing, and a gate
// that passes having scanned nothing is worse than no gate at all.
const minCorpusFiles = 5000

// corpusMaxFileBytes mirrors the default scheduled deep-scan limit. Files
// above it are coverage gaps in production, not content presented to YARA, so
// they cannot provide evidence for this false-positive gate or satisfy its
// minimum corpus floor.
const corpusMaxFileBytes int64 = 16 * 1024 * 1024

// corpusBaseline records rules known to fire on clean third-party code, with
// the observed hit count. Measured 2026-08-21 over 15,992 files of unpacked
// WordPress core and popular plugins: the shipped 152-rule set fires on NONE
// of them, so the baseline is empty and must stay that way.
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

	result, err := scanCleanCorpus(root, minCorpusFiles, corpusMaxFileBytes, func(data []byte) ([]csmyara.Match, error) {
		// Use the same checked, backend-agnostic boundary as the scheduled
		// deep scan. Plain Scanner.ScanBytes flattens an engine failure into a
		// clean result and would let the corpus gate measure the wrong outcome.
		return csmyara.ScanBytesChecked(scanner, data)
	})
	if err != nil {
		t.Fatal(err)
	}

	var regressions []string
	for name, count := range result.hits {
		if count > corpusBaseline[name] {
			regressions = append(regressions, name)
		}
	}
	sort.Strings(regressions)
	for _, name := range regressions {
		t.Errorf("rule %s fired %d times on clean third-party code (baseline %d), first at %s",
			name, result.hits[name], corpusBaseline[name], result.examples[name])
	}
	t.Logf("scanned %d files with %d rules; %d rules fired", result.scanned, scanner.RuleCount(), len(result.hits))
}

type cleanCorpusResult struct {
	hits     map[string]int
	examples map[string]string
	scanned  int
}

type cleanCorpusScanFunc func([]byte) ([]csmyara.Match, error)
type cleanCorpusWalkFunc func(string, filepath.WalkFunc) error
type cleanCorpusReadFileFunc func(string, int64) ([]byte, error)

func scanCleanCorpus(root string, minFiles int, maxFileBytes int64, scan cleanCorpusScanFunc) (cleanCorpusResult, error) {
	return scanCleanCorpusWith(root, minFiles, maxFileBytes, scan, filepath.Walk, readCorpusFile)
}

func scanCleanCorpusWith(
	root string,
	minFiles int,
	maxFileBytes int64,
	scan cleanCorpusScanFunc,
	walk cleanCorpusWalkFunc,
	readFile cleanCorpusReadFileFunc,
) (cleanCorpusResult, error) {
	result := cleanCorpusResult{
		hits:     make(map[string]int),
		examples: make(map[string]string),
	}
	err := walk(root, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return fmt.Errorf("walking %s: %w", path, walkErr)
		}
		if !info.Mode().IsRegular() || info.Size() == 0 || info.Size() > maxFileBytes {
			return nil
		}
		data, err := readFile(path, maxFileBytes)
		if err != nil {
			return fmt.Errorf("reading %s: %w", path, err)
		}
		if int64(len(data)) > maxFileBytes {
			return fmt.Errorf("reading %s: file grew beyond the %d-byte scan limit", path, maxFileBytes)
		}
		// Production intentionally does not present raw compressed archive
		// bytes to YARA. Do not let skipped containers satisfy a floor meant
		// to prove that enough files actually reached the rule engine.
		if contenttype.IsCompressedArchive(data) {
			return nil
		}
		matches, err := scan(data)
		if err != nil {
			return fmt.Errorf("scanning %s: %w", path, err)
		}
		result.scanned++
		for _, match := range matches {
			result.hits[match.RuleName]++
			if _, seen := result.examples[match.RuleName]; !seen {
				result.examples[match.RuleName] = path
			}
		}
		return nil
	})
	if err != nil {
		return cleanCorpusResult{}, fmt.Errorf("walking corpus: %w", err)
	}
	if result.scanned < minFiles {
		return cleanCorpusResult{}, fmt.Errorf(
			"corpus scanned %d files, below the %d-file floor -- check YARA_FP_CORPUS",
			result.scanned, minFiles,
		)
	}
	return result, nil
}

func readCorpusFile(path string, maxFileBytes int64) ([]byte, error) {
	file, err := os.Open(path) // #nosec G304 -- operator-supplied corpus path
	if err != nil {
		return nil, err
	}
	data, readErr := io.ReadAll(io.LimitReader(file, maxFileBytes+1))
	closeErr := file.Close()
	if readErr != nil {
		return nil, readErr
	}
	if closeErr != nil {
		return nil, closeErr
	}
	if int64(len(data)) > maxFileBytes {
		return nil, fmt.Errorf("file exceeds the %d-byte scan limit", maxFileBytes)
	}
	return data, nil
}
