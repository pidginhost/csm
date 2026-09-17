//go:build yara

package signatures

import (
	"os"
	"path/filepath"
	"testing"

	yara_x "github.com/VirusTotal/yara-x/go"
)

func TestPHPGotoYARAParity(t *testing.T) {
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
	yaml := loadRepoScanner(t)
	for _, sample := range phpGotoCases() {
		t.Run(sample.name, func(t *testing.T) {
			content := []byte(sample.content)
			results, err := scanner.Scan(content)
			if err != nil {
				t.Fatal(err)
			}
			got := false
			for _, rule := range results.MatchingRules() {
				if rule.Identifier() == "php_goto_obfuscation" {
					got = true
				}
			}
			if got != sample.want {
				t.Errorf("YARA match = %t, want %t", got, sample.want)
			}
			if yamlGot := hasRule(yaml.ScanContent(content, ".php"), "php_goto_obfuscation"); yamlGot != got {
				t.Errorf("engines disagree: YAML = %t, YARA = %t", yamlGot, got)
			}
		})
	}
}
