//go:build !yara

package yara

// Scanner is a no-op stub when YARA-X is not compiled in.
type Scanner struct{}

// Match represents a YARA rule that matched.
type Match struct {
	RuleName string
}

// NewScanner returns nil when YARA-X is not available.
func NewScanner(_ string) (*Scanner, error) {
	return nil, nil
}

// Reload is a no-op without YARA-X.
func (s *Scanner) Reload() error { return nil }

// ScanBytes returns nil without YARA-X.
func (s *Scanner) ScanBytes(_ []byte) []Match { return nil }

// ScanFile returns nil without YARA-X.
func (s *Scanner) ScanFile(_ string, _ int) []Match { return nil }

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
