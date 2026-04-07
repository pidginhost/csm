//go:build yara

package yara

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	yara_x "github.com/VirusTotal/yara-x/go"
)

// Scanner wraps YARA-X for malware file scanning.
type Scanner struct {
	mu        sync.RWMutex
	rules     *yara_x.Rules
	rulesDir  string
	ruleCount int
}

// NewScanner creates a YARA-X scanner by compiling all .yar/.yara files
// in the given directory.
func NewScanner(rulesDir string) (*Scanner, error) {
	s := &Scanner{rulesDir: rulesDir}
	if err := s.Reload(); err != nil {
		return nil, err
	}
	return s, nil
}

// Reload recompiles all YARA rules from the rules directory.
// Thread-safe - can be called on SIGHUP.
func (s *Scanner) Reload() error {
	if s.rulesDir == "" {
		return nil
	}

	entries, err := os.ReadDir(s.rulesDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("reading YARA rules dir: %w", err)
	}

	compiler, err := yara_x.NewCompiler()
	if err != nil {
		return fmt.Errorf("creating YARA compiler: %w", err)
	}

	ruleCount := 0
	for _, entry := range entries {
		name := entry.Name()
		ext := strings.ToLower(filepath.Ext(name))
		if ext != ".yar" && ext != ".yara" {
			continue
		}

		path := filepath.Join(s.rulesDir, name)
		data, err := os.ReadFile(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "yara: error reading %s: %v\n", path, err)
			continue
		}

		if err := compiler.AddSource(string(data)); err != nil {
			fmt.Fprintf(os.Stderr, "yara: error compiling %s: %v\n", path, err)
			continue
		}
		ruleCount++
	}

	if ruleCount == 0 {
		return nil
	}

	rules := compiler.Build()

	s.mu.Lock()
	s.rules = rules
	s.ruleCount = rules.Count()
	s.mu.Unlock()

	fmt.Fprintf(os.Stderr, "yara: compiled %d rules from %d file(s) in %s\n", s.ruleCount, ruleCount, s.rulesDir)
	return nil
}

// Match represents a YARA rule that matched a file.
type Match struct {
	RuleName string
}

// ScanBytes scans raw bytes against compiled YARA rules.
func (s *Scanner) ScanBytes(data []byte) []Match {
	s.mu.RLock()
	rules := s.rules
	s.mu.RUnlock()

	if rules == nil {
		return nil
	}

	results, err := rules.Scan(data)
	if err != nil {
		return nil
	}

	var matches []Match
	for _, r := range results.MatchingRules() {
		matches = append(matches, Match{RuleName: r.Identifier()})
	}
	return matches
}

// ScanFile reads a file (up to maxBytes) and scans it against YARA rules.
func (s *Scanner) ScanFile(path string, maxBytes int) []Match {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer func() { _ = f.Close() }()

	buf := make([]byte, maxBytes)
	n, _ := f.Read(buf)
	if n == 0 {
		return nil
	}
	return s.ScanBytes(buf[:n])
}

// RuleCount returns the number of compiled rule files.
func (s *Scanner) RuleCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.ruleCount
}

// GlobalRules returns the compiled YARA-X rules for sharing with other scanners
// (e.g., the email AV YaraXScanner adapter). Thread-safe.
func (s *Scanner) GlobalRules() *yara_x.Rules {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.rules
}

// Available returns true (YARA-X is compiled in).
func Available() bool {
	return true
}

// TestCompile attempts to compile a YARA rule source string.
// Returns nil if compilation succeeds, error otherwise.
// Used by the Forge fetcher to validate downloaded rules before installing.
func TestCompile(source string) error {
	compiler, err := yara_x.NewCompiler()
	if err != nil {
		return fmt.Errorf("creating YARA compiler: %w", err)
	}
	if err := compiler.AddSource(source); err != nil {
		return fmt.Errorf("compiling rules: %w", err)
	}
	rules := compiler.Build()
	if rules.Count() == 0 {
		return fmt.Errorf("no rules compiled from source")
	}
	return nil
}
