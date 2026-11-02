package antispam

import (
	"slices"
	"testing"
)

func TestResolveScoresUCLDefinitions(t *testing.T) {
	for name, content := range map[string]string{
		"quoted hash":          `description = "Policy #1"; symbols { DMARC_POLICY_REJECT { weight = 5; } }`,
		"escaped quotes":       `description = "Policy \"#1\""; symbols { DMARC_POLICY_REJECT { weight = 5; } }`,
		"quoted block markers": `description = "/*"; symbols { DMARC_POLICY_REJECT { weight = 5; description = "*/"; } }`,
		"escaped key":          `symbols { "DMARC_POLICY_\u0052EJECT" { weight = 5; } }`,
		"nested comment":       `symbols { DMARC_POLICY_REJECT /* outer /* inner */ rest */ { weight = 5; } }`,
		"quoted comment end":   `/* "*/ # " */ symbols { DMARC_POLICY_REJECT { weight = 5; } }`,
		"array":                `symbols { DMARC_POLICY_REJECT = [{ weight = 5; }]; }`,
	} {
		t.Run(name, func(t *testing.T) {
			f := feedFacts()
			f.GroupFiles = map[string]GroupFile{"policies": {Content: content}}
			got, problems := ResolveScores(defaults(false), f)
			if got.SkipScores || !slices.Equal(got.HostScores, []string{"DMARC_POLICY_REJECT"}) || len(problems) != 0 {
				t.Fatalf("host scores %q, skip %v, problems %+v", got.HostScores, got.SkipScores, problems)
			}
		})
	}
}

func TestResolveScoresIndirectDefinitions(t *testing.T) {
	for name, content := range map[string]string{
		"include":          `.include "custom-scores.conf"`,
		"include options":  `.include(try=true, glob=true) "custom/*.conf"`,
		"multiline string": "description = <<END\n/* example\nEND\nsymbols { DMARC_POLICY_REJECT { weight = 5; } }\n",
	} {
		t.Run(name, func(t *testing.T) {
			f := feedFacts()
			f.GroupFiles = map[string]GroupFile{"policies": {Content: content}}
			got, problems := ResolveScores(defaults(false), f)
			if got.SkipScores || !slices.Equal(got.HostScores, []string{"HIDDEN_TEXT", "URL_VERY_LONG", "DMARC_POLICY_REJECT"}) || len(problems) != 0 {
				t.Fatalf("unresolved UCL must leave weights to the host: %q, skip %v, problems %+v", got.HostScores, got.SkipScores, problems)
			}
		})
	}
}

func TestDefinesSymbolIgnoresCommentsAndOtherTokens(t *testing.T) {
	for _, content := range []string{
		`/* outer /* inner */ DMARC_POLICY_REJECT { weight = 5; } */`,
		`description = "Use DMARC_POLICY_REJECT { weight = 5; }";`,
		`description = '.include "custom.conf"';`,
		`symbols { OTHER_SYMBOL { weight = .5; } }`,
		"# .include \"custom.conf\"\nsymbols {}",
		`symbols { NOT_DMARC_POLICY_REJECT { weight = 5; } DMARC_POLICY_REJECT_EXTRA { weight = 5; } }`,
	} {
		if definesSymbol(content, "DMARC_POLICY_REJECT") {
			t.Errorf("comment or other token treated as a definition: %q", content)
		}
	}
}
