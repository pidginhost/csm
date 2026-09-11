//go:build yara

package signatures

import (
	"os"
	"path/filepath"
	"testing"

	yara_x "github.com/VirusTotal/yara-x/go"
)

func TestExploitWpAdminCreation_YARACreationShapes(t *testing.T) {
	source, err := os.ReadFile(filepath.Join("..", "..", "configs", "malware.yar"))
	if err != nil {
		t.Fatal(err)
	}
	rules, err := yara_x.Compile(string(source))
	if err != nil {
		t.Fatal(err)
	}
	defer rules.Destroy()
	scanner := yara_x.NewScanner(rules)
	defer scanner.Destroy()
	checkWPAdminCreationSamples(t, func(t *testing.T, source string) bool {
		t.Helper()
		results, err := scanner.Scan([]byte(source))
		if err != nil {
			t.Fatal(err)
		}
		for _, rule := range results.MatchingRules() {
			if rule.Identifier() == "exploit_wp_admin_creation" {
				return true
			}
		}
		return false
	})
}
