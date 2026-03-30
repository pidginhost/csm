//go:build !yara

package emailav

// YaraXScanner is a no-op stub when YARA-X is not compiled in.
type YaraXScanner struct{}

// NewYaraXScanner returns a scanner that is never available.
func NewYaraXScanner(_ interface{}) *YaraXScanner {
	return &YaraXScanner{}
}

func (s *YaraXScanner) Name() string             { return "yara-x" }
func (s *YaraXScanner) Available() bool           { return false }
func (s *YaraXScanner) Scan(_ string) (Verdict, error) {
	return Verdict{}, nil
}
