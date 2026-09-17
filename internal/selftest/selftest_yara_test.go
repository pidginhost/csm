//go:build yara

package selftest

import (
	"testing"

	"github.com/pidginhost/csm/internal/yara"
)

// The same gate over the YARA-X rules, which cover scheduled and email
// scanning. It only builds with the yara tag, which is what CI ships.
func TestYaraRulesMatchTheBundle(t *testing.T) {
	scanner, err := yara.NewScanner("../../configs")
	if err != nil {
		t.Fatalf("loading YARA rules: %v", err)
	}
	if scanner.RuleCount() == 0 {
		t.Fatal("no YARA rules loaded; the gate would pass vacuously")
	}
	results := Run(Yara, func(content []byte, _ string) ([]string, error) {
		matches, err := scanner.ScanBytesChecked(content)
		if err != nil {
			return nil, err
		}
		var names []string
		for _, m := range matches {
			names = append(names, m.RuleName)
		}
		return names, nil
	})
	assertBundle(t, Yara, results)
}
