//go:build !yara

package emailav

import "github.com/pidginhost/csm/internal/yara"

// YaraXScanner is a no-op stub when YARA-X is not compiled in. The
// constructor still accepts a yara.Backend so callers can pass
// yara.Active() uniformly across build tags.
type YaraXScanner struct{}

// NewYaraXScanner returns a scanner that is never available.
func NewYaraXScanner(_ yara.Backend) *YaraXScanner {
	return &YaraXScanner{}
}

func (s *YaraXScanner) Name() string    { return "yara-x" }
func (s *YaraXScanner) Available() bool { return false }
func (s *YaraXScanner) Scan(_ string) (Verdict, error) {
	return Verdict{}, nil
}
