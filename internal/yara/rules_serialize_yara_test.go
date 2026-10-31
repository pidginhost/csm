//go:build yara

package yara

import (
	"bytes"
	"strings"
	"testing"
)

func TestCompiledRulesRoundTrip(t *testing.T) {
	compiled, err := CompileSources([]Source{{
		Name: "marker.yar",
		Text: []byte(`rule csm_roundtrip_marker { meta: severity = "critical" strings: $a = "CSM-ROUNDTRIP-7c1e" condition: $a }`),
	}})
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if _, err := compiled.WriteTo(&buf); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadRules(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if compiled.Count() != 1 || loaded.Count() != 1 {
		t.Fatalf("counts compiled=%d loaded=%d, want 1", compiled.Count(), loaded.Count())
	}
	matches, err := loaded.Scan([]byte("xx CSM-ROUNDTRIP-7c1e xx"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 1 || matches[0].RuleName != "csm_roundtrip_marker" || matches[0].Meta["severity"] != "critical" {
		t.Fatalf("matches = %+v", matches)
	}
	clean, err := loaded.Scan([]byte("nothing here"))
	if err != nil || len(clean) != 0 {
		t.Fatalf("clean scan = %+v, %v", clean, err)
	}
}

func TestCompileSourcesNamesFailingFile(t *testing.T) {
	_, err := CompileSources([]Source{
		{Name: "good.yar", Text: []byte("rule good { condition: true }")},
		{Name: "bad.yar", Text: []byte("rule {")},
	})
	if err == nil || !strings.Contains(err.Error(), "bad.yar") {
		t.Fatalf("err = %v, want one naming bad.yar", err)
	}
}

func TestLoadRulesRejectsGarbage(t *testing.T) {
	if _, err := LoadRules(strings.NewReader("not rules")); err == nil {
		t.Fatal("garbage must not load as rules")
	}
}
