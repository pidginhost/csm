package signatures

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"gopkg.in/yaml.v3"
)

var (
	yaraMetaSeverity = regexp.MustCompile(`(?m)^\s*severity\s*=\s*"([a-z]+)"`)
	yaraMetaCategory = regexp.MustCompile(`(?m)^\s*category\s*=\s*"([a-z_]+)"`)
)

// Realtime acts on its own verdicts: a dropper or webshell match there is
// quarantined inline (isHighConfidenceRealtimeMatch). A realtime rule graded
// harsher than its scan twin quarantines files every scan grades lower.
func TestRealtimeRulesNotGradedAboveYARATwins(t *testing.T) {
	configsDir := filepath.Join("..", "..", "configs")
	yamlData, err := os.ReadFile(filepath.Join(configsDir, "malware.yml"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Rules []struct {
			Name     string `yaml:"name"`
			Severity string `yaml:"severity"`
			Category string `yaml:"category"`
		} `yaml:"rules"`
	}
	if unmarshalErr := yaml.Unmarshal(yamlData, &doc); unmarshalErr != nil {
		t.Fatal(unmarshalErr)
	}
	yaraData, err := os.ReadFile(filepath.Join(configsDir, "malware.yar"))
	if err != nil {
		t.Fatal(err)
	}
	decls := yaraRuleDeclaration.FindAllSubmatchIndex(maskYARACommentsAndLiterals(yaraData), -1)
	type grade struct{ severity, category string }
	twins := make(map[string]grade, len(decls))
	for i, d := range decls {
		end := len(yaraData)
		if i+1 < len(decls) {
			end = decls[i+1][0]
		}
		body := yaraData[d[0]:end]
		var g grade
		if m := yaraMetaSeverity.FindSubmatch(body); m != nil {
			g.severity = string(m[1])
		}
		if m := yaraMetaCategory.FindSubmatch(body); m != nil {
			g.category = string(m[1])
		}
		twins[string(yaraData[d[2]:d[3]])] = g
	}
	if twins["webshell_wso"].severity != "critical" {
		t.Fatalf("YARA meta parse broken: webshell_wso = %+v", twins["webshell_wso"])
	}
	for _, rule := range doc.Rules {
		twin, ok := twins[rule.Name]
		if !ok {
			continue
		}
		if rule.Severity != twin.severity {
			t.Errorf("%s: realtime severity %s, YARA %s", rule.Name, rule.Severity, twin.severity)
		}
		if (rule.Category == "dropper" || rule.Category == "webshell") && rule.Category != twin.category {
			t.Errorf("%s: realtime category %s quarantines inline, YARA category %s", rule.Name, rule.Category, twin.category)
		}
	}
}
