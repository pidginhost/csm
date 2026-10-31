//go:build yara

package yara

import (
	"fmt"
	"io"
	"os"
	"sync"

	yara_x "github.com/VirusTotal/yara-x/go"
)

// Scanner wraps YARA-X for malware file scanning.
type Scanner struct {
	mu            sync.RWMutex
	rules         *yara_x.Rules
	rulesDir      string
	ruleCount     int
	disabled      []string
	disabledCount int
}

// NewScanner creates a YARA-X scanner by compiling all .yar/.yara files
// in the given directory. Rule names in disabled are stripped before
// compilation, alongside the built-in suppressions.
func NewScanner(rulesDir string, disabled ...string) (*Scanner, error) {
	s := &Scanner{rulesDir: rulesDir, disabled: disabled}
	if err := s.Reload(); err != nil {
		return nil, err
	}
	return s, nil
}

// DisabledRules returns the operator-configured rule names this scanner
// strips before compiling.
func (s *Scanner) DisabledRules() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]string(nil), s.disabled...)
}

// DisabledRuleCount counts rules omitted from the installed ruleset by config
// or built-in suppressions.
func (s *Scanner) DisabledRuleCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.disabledCount
}

// Reload recompiles all YARA rules from the rules directory.
// Thread-safe - can be called on SIGHUP.
func (s *Scanner) Reload() error {
	if s.rulesDir == "" {
		return nil
	}
	if _, err := os.Stat(s.rulesDir); os.IsNotExist(err) {
		return nil
	}
	sources, disabledCount, err := ReadSources(s.rulesDir, s.disabled)
	if err != nil {
		return err
	}

	if len(sources) == 0 {
		s.mu.RLock()
		hadRules := s.rules != nil || s.ruleCount > 0
		s.mu.RUnlock()
		if hadRules {
			return fmt.Errorf("no YARA rule files found in %s", s.rulesDir)
		}
		return nil
	}

	compiled, err := CompileSources(sources)
	if err != nil {
		return err
	}
	rules := compiled.rules
	if rules.Count() == 0 && disabledCount == 0 {
		return fmt.Errorf("no YARA rules compiled from %s", s.rulesDir)
	}

	s.mu.Lock()
	s.rules = rules
	s.ruleCount = rules.Count()
	s.disabledCount = disabledCount
	InvalidateCaches()
	s.mu.Unlock()

	fmt.Fprintf(os.Stderr, "yara: compiled %d rules from %d file(s) in %s\n", s.ruleCount, len(sources), s.rulesDir)
	return nil
}

// Rules is a compiled rule set that can be saved and loaded again without
// recompiling, so one process can compile what another scans with.
type Rules struct {
	rules *yara_x.Rules
}

// CompileSources compiles sources into one rule set. A compile failure names
// the source it came from.
func CompileSources(sources []Source) (*Rules, error) {
	compiler, err := yara_x.NewCompiler()
	if err != nil {
		return nil, fmt.Errorf("creating YARA compiler: %w", err)
	}
	for _, src := range sources {
		if err := compiler.AddSource(string(src.Text)); err != nil {
			return nil, fmt.Errorf("compiling %s: %w", src.Name, err)
		}
	}
	return &Rules{rules: compiler.Build()}, nil
}

// LoadRules reads a rule set that Rules.WriteTo saved.
func LoadRules(r io.Reader) (*Rules, error) {
	rules, err := yara_x.ReadFrom(r)
	if err != nil {
		return nil, fmt.Errorf("loading compiled YARA rules: %w", err)
	}
	return &Rules{rules: rules}, nil
}

// Count is the number of rules in the set.
func (r *Rules) Count() int { return r.rules.Count() }

// WriteTo saves the compiled rule set.
func (r *Rules) WriteTo(w io.Writer) (int64, error) { return r.rules.WriteTo(w) }

// Scan scans data and returns the matching rules with their string metadata.
// An engine error is returned, never flattened to no matches.
func (r *Rules) Scan(data []byte) ([]Match, error) {
	results, err := r.rules.Scan(data)
	if err != nil {
		return nil, fmt.Errorf("yara scan: %w", err)
	}
	var matches []Match
	for _, m := range results.MatchingRules() {
		matches = append(matches, Match{
			RuleName: m.Identifier(),
			Meta:     extractStringMeta(m.Metadata()),
		})
	}
	return matches, nil
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

	// No content policy here: the engine scans whatever it is handed. Whether
	// a payload should reach it (the archive skip) is decided at the daemon
	// boundary in ScanBytesChecked, which knows the file name; the worker
	// process behind the IPC backend only ever sees bytes.
	return (&Rules{rules: rules}).Scan(data)
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
	compiled, err := CompileSources([]Source{{Name: "source", Text: []byte(source)}})
	if err != nil {
		return err
	}
	if compiled.Count() == 0 {
		return fmt.Errorf("no rules compiled from source")
	}
	return nil
}
