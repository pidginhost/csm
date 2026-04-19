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

	fileCount := 0
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() {
			continue
		}
		ext := strings.ToLower(filepath.Ext(name))
		if ext != ".yar" && ext != ".yara" {
			continue
		}
		fileCount++

		path := filepath.Join(s.rulesDir, name)
		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("reading %s: %w", path, err)
		}

		if err := compiler.AddSource(string(data)); err != nil {
			return fmt.Errorf("compiling %s: %w", path, err)
		}
	}

	if fileCount == 0 {
		s.mu.RLock()
		hadRules := s.rules != nil || s.ruleCount > 0
		s.mu.RUnlock()
		if hadRules {
			return fmt.Errorf("no YARA rule files found in %s", s.rulesDir)
		}
		return nil
	}

	rules := compiler.Build()
	if rules.Count() == 0 {
		return fmt.Errorf("no YARA rules compiled from %s", s.rulesDir)
	}

	s.mu.Lock()
	s.rules = rules
	s.ruleCount = rules.Count()
	s.mu.Unlock()

	fmt.Fprintf(os.Stderr, "yara: compiled %d rules from %d file(s) in %s\n", s.ruleCount, fileCount, s.rulesDir)
	return nil
}

// Match represents a YARA rule that matched a file. Meta carries
// string-valued rule metadata pulled from YARA-X `rule.Metadata()` at
// scan time: severity, description, author, and anything else the rule
// author wrote as a string. Non-string metadata (int / float / bool /
// bytes) is dropped — wiring only strings is a deliberate policy, not a
// fidelity claim. Consumers (e.g. emailav) own their own defaults for
// missing keys.
type Match struct {
	RuleName string
	Meta     map[string]string
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
		matches = append(matches, Match{
			RuleName: r.Identifier(),
			Meta:     extractStringMeta(r.Metadata()),
		})
	}
	return matches
}

// extractStringMeta projects YARA-X metadata entries whose Value() is a
// string into a map[string]string. Non-string entries are dropped: the
// IPC wire format and all current consumers deal in strings, and
// promoting numbers/bools/bytes through that boundary would expand the
// surface without a concrete reader. Returns nil when no string
// metadata is present so clean scans do not allocate.
func extractStringMeta(entries []yara_x.Metadata) map[string]string {
	if len(entries) == 0 {
		return nil
	}
	var out map[string]string
	for _, m := range entries {
		v, ok := m.Value().(string)
		if !ok {
			continue
		}
		if out == nil {
			out = make(map[string]string, len(entries))
		}
		out[m.Identifier()] = v
	}
	return out
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
