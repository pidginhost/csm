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
	results := Run(Yara, func(content []byte, _ string) []string {
		var names []string
		for _, m := range scanner.ScanBytes(content) {
			names = append(names, m.RuleName)
		}
		return names
	})
	assertBundle(t, Yara, results)
}
