package signatures

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"sync"
	"testing"
)

// The shipped corpus gate compiles malware.yar only, so the rules that run in
// realtime and in finding re-check had never been measured against clean code.
// This is the same measurement for the other engine.
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
	// Registration mail in Elementor and WooCommerce add-ons.
	"credential_mailer": 4,
	// The PHPMailer SMTP class shipped in WordPress core.
	"mailer_exim_exploit": 1,
	// The FTP sockets class shipped in WordPress core.
	"network_http_tunnel": 1,
	// A scanner plugin's engine and core comment handling.
	"spam_comment_injector": 3,
	// Minified plugin JavaScript naming a card field near a network call.
	"wp_woocommerce_card_skimmer": 10,
}

func TestRepositoryYAMLRulesAgainstCleanCorpus(t *testing.T) {
	root := os.Getenv("YARA_FP_CORPUS")
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

	var regressions []string
	for name, count := range hits {
		if count > yamlCorpusBaseline[name] {
			regressions = append(regressions, name)
		}
	}
	sort.Strings(regressions)
	for _, name := range regressions {
		t.Errorf("rule %s fired %d times on clean third-party code (baseline %d), first at %s",
			name, hits[name], yamlCorpusBaseline[name], examples[name])
	}
	t.Logf("scanned %d files; %d rules fired", scanned, len(hits))
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
