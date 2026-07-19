//go:build yara

package yara

import (
	"crypto/sha256"
	"fmt"
	"io"
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

	// Refuse to compile rules from a directory or file that a third
	// party could overwrite. An attacker who can drop a blank rule
	// silently disables every detection downstream of YARA - the
	// scanner stays "Available" with rule_count > 0 while matching
	// nothing.
	if err := validateRulesDir(s.rulesDir); err != nil {
		return err
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

// ScanBytes scans raw bytes against compiled YARA rules. A scan engine error
// is flattened to "no matches"; callers that must distinguish a failed scan
// from a clean file should use ScanBytesChecked.
func (s *Scanner) ScanBytes(data []byte) []Match {
	m, _ := s.ScanBytesChecked(data)
	return m
}

// ScanBytesChecked scans raw bytes and returns a non-nil error when the YARA
// engine itself failed, so a caller can tell a real clean result from a scan
// that could not complete.
func (s *Scanner) ScanBytesChecked(data []byte) ([]Match, error) {
	s.mu.RLock()
	rules := s.rules
	s.mu.RUnlock()

	if rules == nil {
		return nil, nil
	}

	results, err := rules.Scan(data)
	if err != nil {
		return nil, fmt.Errorf("yara scan: %w", err)
	}

	var matches []Match
	for _, r := range results.MatchingRules() {
		matches = append(matches, Match{
			RuleName: r.Identifier(),
			Meta:     extractStringMeta(r.Metadata()),
		})
	}
	return matches, nil
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

// ScanFile reads up to maxBytes from a file and flattens read or scan failures
// to no matches. It retains the legacy prefix-scan behavior for callers that
// use the error-free Backend interface.
func (s *Scanner) ScanFile(path string, maxBytes int) []Match {
	if maxBytes <= 0 {
		return nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer func() { _ = f.Close() }()

	buf, err := io.ReadAll(io.LimitReader(f, int64(maxBytes)))
	if err != nil || len(buf) == 0 {
		return nil
	}
	return s.ScanBytes(buf)
}

// ScanFileChecked reads a file up to maxBytes and returns a non-nil error when
// the file cannot be read completely or the YARA engine fails.
func (s *Scanner) ScanFileChecked(path string, maxBytes int) (FileScanResult, error) {
	if maxBytes <= 0 {
		return FileScanResult{}, fmt.Errorf("yara scan file: maxBytes must be positive")
	}
	f, err := os.Open(path)
	if err != nil {
		return FileScanResult{}, fmt.Errorf("yara scan file: open %s: %w", path, err)
	}

	// ReadAll over a LimitReader rather than one f.Read into a pre-sized
	// buffer: a short first read would scan only a prefix and silently miss
	// malware deeper in the file, and a negative maxBytes off the IPC wire
	// would panic make([]byte, maxBytes).
	buf, readErr := io.ReadAll(io.LimitReader(f, int64(maxBytes)))
	var limitErr error
	if readErr == nil && len(buf) == maxBytes {
		var extra [1]byte
		n, extraErr := f.Read(extra[:])
		switch {
		case n > 0:
			limitErr = fmt.Errorf("yara scan file: %s exceeds %d-byte limit", path, maxBytes)
		case extraErr != nil && extraErr != io.EOF:
			readErr = extraErr
		}
	}
	closeErr := f.Close()
	if readErr != nil {
		return FileScanResult{}, fmt.Errorf("yara scan file: read %s: %w", path, readErr)
	}
	if closeErr != nil {
		return FileScanResult{}, fmt.Errorf("yara scan file: close %s: %w", path, closeErr)
	}
	if limitErr != nil {
		return FileScanResult{}, limitErr
	}
	matches, err := s.ScanBytesChecked(buf)
	if err != nil {
		return FileScanResult{}, err
	}
	digest := sha256.Sum256(buf)
	return FileScanResult{Matches: matches, ContentSHA256: fmt.Sprintf("%x", digest)}, nil
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
