//go:build yara

package emailav

import (
	"fmt"
	"os"

	yara_x "github.com/VirusTotal/yara-x/go"
)

// YaraXScanner wraps compiled YARA-X rules for email attachment scanning.
// Unlike internal/yara.Scanner, this adapter extracts rule metadata (severity)
// and returns Verdict types compatible with the emailav Scanner interface.
type YaraXScanner struct {
	rules    *yara_x.Rules
	supplier interface {
		GlobalRules() *yara_x.Rules
	}
}

// NewYaraXScanner creates a scanner from pre-compiled rules.
// Pass the same *yara_x.Rules used by the filesystem scanner so hot-reload works.
func NewYaraXScanner(source any) *YaraXScanner {
	switch v := source.(type) {
	case *yara_x.Rules:
		return &YaraXScanner{rules: v}
	case interface{ GlobalRules() *yara_x.Rules }:
		return &YaraXScanner{supplier: v}
	default:
		return &YaraXScanner{}
	}
}

func (s *YaraXScanner) Name() string { return "yara-x" }

func (s *YaraXScanner) Available() bool {
	return s.currentRules() != nil
}

// Scan reads the file and matches against compiled YARA rules.
// Returns the first matching rule's verdict (with severity from rule metadata).
func (s *YaraXScanner) Scan(path string) (Verdict, error) {
	rules := s.currentRules()
	if rules == nil {
		return Verdict{}, fmt.Errorf("no YARA rules compiled")
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return Verdict{}, fmt.Errorf("reading file: %w", err)
	}

	results, err := rules.Scan(data)
	if err != nil {
		return Verdict{}, fmt.Errorf("scanning: %w", err)
	}

	matching := results.MatchingRules()
	if len(matching) == 0 {
		return Verdict{Infected: false}, nil
	}

	// Use the first matching rule
	rule := matching[0]
	severity := "high" // default if rule has no severity metadata
	for _, m := range rule.Metadata() {
		if m.Identifier() == "severity" {
			if s, ok := m.Value().(string); ok {
				severity = s
			}
		}
	}

	return Verdict{
		Infected:  true,
		Signature: rule.Identifier(),
		Severity:  severity,
	}, nil
}

func (s *YaraXScanner) currentRules() *yara_x.Rules {
	if s.supplier != nil {
		return s.supplier.GlobalRules()
	}
	return s.rules
}
