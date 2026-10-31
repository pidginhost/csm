//go:build !yara

package yara

import "io"

// Scanner is a no-op stub when YARA-X is not compiled in.
type Scanner struct{}

// Match represents a YARA rule that matched. Meta carries string-valued
// rule metadata pulled from `rule.Metadata()` (see yarax build); under
// this stub no rule ever matches, so Meta is never populated.
type Match struct {
	RuleName string
	Meta     map[string]string
}

// NewScanner returns nil when YARA-X is not available.
func NewScanner(_ string, _ ...string) (*Scanner, error) {
	return nil, nil
}

// DisabledRules returns nothing without YARA-X; no rules are compiled.
func (s *Scanner) DisabledRules() []string { return nil }

// DisabledRuleCount returns zero without YARA-X.
func (s *Scanner) DisabledRuleCount() int { return 0 }

// Reload is a no-op without YARA-X.
func (s *Scanner) Reload() error { return nil }

// ScanBytes returns nil without YARA-X.
func (s *Scanner) ScanBytes(_ []byte) []Match { return nil }

// ScanBytesChecked returns nil without YARA-X; there is no engine to fail.
func (s *Scanner) ScanBytesChecked(_ []byte) ([]Match, error) { return nil, nil }

// RuleCount returns 0 without YARA-X.
func (s *Scanner) RuleCount() int { return 0 }

// GlobalRules returns nil without YARA-X (no compiled rules available).
func (s *Scanner) GlobalRules() interface{} { return nil }

// Available returns false (YARA-X is not compiled in).
func Available() bool {
	return false
}

// TestCompile is a no-op when YARA-X is not compiled in.
func TestCompile(source string) error {
	return nil
}

// Rules is an empty stand-in: without YARA-X nothing compiles or loads.
type Rules struct{}

// CompileSources returns ErrNoEngine without YARA-X.
func CompileSources(_ []Source) (*Rules, error) { return nil, ErrNoEngine }

// CompileIsolatedSources returns ErrNoEngine without YARA-X.
func CompileIsolatedSources(_ []Source) (*Rules, error) { return nil, ErrNoEngine }

// LoadRules returns ErrNoEngine without YARA-X.
func LoadRules(_ io.Reader) (*Rules, error) { return nil, ErrNoEngine }

// Count returns 0 without YARA-X.
func (r *Rules) Count() int { return 0 }

// Destroy is a no-op without YARA-X.
func (r *Rules) Destroy() {}

// WriteTo returns ErrNoEngine without YARA-X.
func (r *Rules) WriteTo(_ io.Writer) (int64, error) { return 0, ErrNoEngine }

// Scan returns ErrNoEngine without YARA-X.
func (r *Rules) Scan(_ []byte) ([]Match, error) { return nil, ErrNoEngine }
