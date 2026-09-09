package signatures

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"

	"github.com/pidginhost/csm/internal/contenttype"
	"github.com/pidginhost/csm/internal/corpusgate"
)

// Measure the production YAML rules against the same public corpus as YARA.
//
// Point YARA_FP_CORPUS at a tree of unpacked WordPress core and plugins:
//
//	YARA_FP_CORPUS=/path/to/corpus go test ./internal/signatures/ -run TestRepositoryYAMLRulesAgainstCleanCorpus -v
//
// The YAML engine lowercases every file it scans, so it is far slower than
// YARA-X on the same tree; the walk is spread across cores to keep the run
// inside the default test timeout.
const (
	minYAMLCorpusFiles           = 5000
	yamlCorpusMaxFileBytes int64 = 16 * 1024 * 1024
)

// yamlCorpusBaseline records rules that fire on clean third-party code, with
// the observed hit count. Every entry is a realtime false positive that the
// porting backlog already names; the file family behind each one is in its
// backlog reason. Adding an entry admits a new one, so tighten the rule first.
var yamlCorpusBaseline = map[string]int{
	// A security plugin's own login handling.
	"credential_logger": 1,
	// The PHPMailer SMTP class shipped in WordPress core.
	"mailer_exim_exploit": 1,
	// A scanner plugin's engine and core comment handling.
	"spam_comment_injector": 3,
	// Minified plugin JavaScript naming a card field near a network call.
	"wp_woocommerce_card_skimmer": 10,
}

func TestRepositoryYAMLRulesAgainstCleanCorpus(t *testing.T) {
	root, rootErr := corpusgate.Root("YARA_FP_CORPUS")
	if rootErr != nil {
		t.Fatal(rootErr)
	}
	if root == "" {
		t.Skip("YARA_FP_CORPUS not set")
	}

	scanner := NewScanner(filepath.Join("..", "..", "configs"))
	if err := scanner.LoadError(); err != nil {
		t.Fatalf("loading YAML rules: %v", err)
	}

	hits, examples, scanned, err := scanCleanCorpusYAML(t, root, scanner)
	if err != nil {
		t.Fatal(err)
	}
	if scanned < minYAMLCorpusFiles {
		t.Fatalf("corpus scanned %d files, below the %d-file floor -- check YARA_FP_CORPUS", scanned, minYAMLCorpusFiles)
	}

	for _, rule := range scanner.rules {
		if _, found := hits[rule.Name]; !found {
			hits[rule.Name] = 0
		}
	}
	report := corpusgate.Report{Engine: "yaml", Scanned: scanned, Hits: hits, Thresholds: yamlCorpusBaseline}
	if err := report.Save(); err != nil {
		t.Fatal(err)
	}
	if err := report.Validate(); err != nil {
		t.Error(err)
	}
	fired := 0
	for rule, count := range hits {
		if count > 0 {
			fired++
			t.Logf("rule %s hits=%d threshold=%d example=%s", rule, count, yamlCorpusBaseline[rule], examples[rule])
		}
	}
	t.Logf("scanned %d files; %d rules fired", scanned, fired)
}

func TestScanCleanCorpusYAMLReturnsWalkError(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing")
	_, _, _, err := scanCleanCorpusYAML(t, missing, &Scanner{})
	if err == nil {
		t.Fatal("walk error was swallowed after workers observed the closed path channel")
	}
}

func TestScanCleanCorpusYAMLSkipsCompressedArchives(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "plugin.zip"), []byte("PK\x03\x04payload"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, _, scanned, err := scanCleanCorpusYAML(t, root, &Scanner{})
	if err != nil {
		t.Fatal(err)
	}
	if scanned != 0 {
		t.Fatalf("compressed archives counted toward corpus floor: scanned = %d, want 0", scanned)
	}
}

func scanCleanCorpusYAML(t *testing.T, root string, scanner *Scanner) (map[string]int, map[string]string, int, error) {
	t.Helper()

	paths := make(chan string)
	var walkErr error
	go func() {
		defer close(paths)
		walkErr = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return fmt.Errorf("walking %s: %w", path, err)
			}
			if !info.Mode().IsRegular() || info.Size() == 0 || info.Size() > yamlCorpusMaxFileBytes {
				return nil
			}
			paths <- path
			return nil
		})
	}()

	var (
		mu       sync.Mutex
		hits     = make(map[string]int)
		examples = make(map[string]string)
		scanned  int
		scanErr  error
		wg       sync.WaitGroup
	)
	for worker := 0; worker < runtime.NumCPU(); worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for path := range paths {
				data, err := readYAMLCorpusFile(path)
				if err != nil {
					mu.Lock()
					if scanErr == nil {
						scanErr = err
					}
					mu.Unlock()
					continue
				}
				if contenttype.IsArchiveFile(path, data) {
					continue
				}
				matches := scanner.ScanContent(data, filepath.Ext(path))
				mu.Lock()
				scanned++
				for _, match := range matches {
					hits[match.RuleName]++
					if _, seen := examples[match.RuleName]; !seen {
						examples[match.RuleName] = path
					}
				}
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	if walkErr != nil {
		return nil, nil, 0, walkErr
	}
	if scanErr != nil {
		return nil, nil, 0, scanErr
	}
	return hits, examples, scanned, nil
}

func readYAMLCorpusFile(path string) ([]byte, error) {
	file, err := os.Open(path) // #nosec G304 -- operator-supplied corpus path
	if err != nil {
		return nil, err
	}
	data, readErr := io.ReadAll(io.LimitReader(file, yamlCorpusMaxFileBytes+1))
	closeErr := file.Close()
	if readErr != nil {
		return nil, fmt.Errorf("reading %s: %w", path, readErr)
	}
	if closeErr != nil {
		return nil, fmt.Errorf("closing %s: %w", path, closeErr)
	}
	if int64(len(data)) > yamlCorpusMaxFileBytes {
		return nil, fmt.Errorf("reading %s: file grew beyond the %d-byte scan limit", path, yamlCorpusMaxFileBytes)
	}
	return data, nil
}

func TestCleanCorpusGateRejectsAlwaysMatchingRule(t *testing.T) {
	rules := t.TempDir()
	body := "version: 1\nrules:\n  - name: bad_detector\n    severity: critical\n    file_types: ['*']\n    patterns: ['<?php']\n    min_match: 1\n"
	if err := os.WriteFile(filepath.Join(rules, "bad.yml"), []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	scanner := NewScanner(rules)
	if err := scanner.LoadError(); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "clean.php"), []byte("<?php echo 'clean';"), 0600); err != nil {
		t.Fatal(err)
	}
	hits, _, scanned, err := scanCleanCorpusYAML(t, root, scanner)
	if err != nil {
		t.Fatal(err)
	}
	if scanned != 1 || hits["bad_detector"] != 1 {
		t.Fatalf("bad rule did not run: scanned=%d hits=%v", scanned, hits)
	}
	if err := (corpusgate.Report{Engine: "yaml", Scanned: scanned, Hits: hits}).Validate(); err == nil {
		t.Fatal("bad detector passed corpus gate")
	}
}
