package yara

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeRulesDir(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "rules")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	for name, text := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestReadSourcesStripsDisabledRules(t *testing.T) {
	dir := writeRulesDir(t, map[string]string{
		"a.yar": "rule keep_a { condition: true }\nrule drop_me { condition: true }\n",
		"b.yar": "rule keep_b { condition: true }\n",
	})
	sources, disabled, err := ReadSources(dir, []string{"drop_me"})
	if err != nil {
		t.Fatal(err)
	}
	if len(sources) != 2 || sources[0].Name != "a.yar" || sources[1].Name != "b.yar" {
		t.Fatalf("sources = %+v, want a.yar then b.yar", sources)
	}
	if strings.Contains(string(sources[0].Text), "drop_me") || !strings.Contains(string(sources[0].Text), "keep_a") {
		t.Fatalf("a.yar text after stripping = %q", sources[0].Text)
	}
	if disabled != 1 {
		t.Fatalf("disabled count = %d, want 1", disabled)
	}
}

func TestReadSourcesSkipsNonRuleFiles(t *testing.T) {
	dir := writeRulesDir(t, map[string]string{
		"a.yar":  "rule a { condition: true }",
		"b.yara": "rule b { condition: true }",
		"c.yml":  "rules: []",
		"d.txt":  "rule d { condition: true }",
	})
	if err := os.Mkdir(filepath.Join(dir, "sub.yar"), 0o700); err != nil {
		t.Fatal(err)
	}
	sources, _, err := ReadSources(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, s := range sources {
		names = append(names, s.Name)
	}
	if strings.Join(names, ",") != "a.yar,b.yara" {
		t.Fatalf("names = %v, want [a.yar b.yara]", names)
	}
}

func TestReadSourcesMissingDirIsEmpty(t *testing.T) {
	for _, dir := range []string{filepath.Join(t.TempDir(), "absent"), ""} {
		sources, disabled, err := ReadSources(dir, []string{"x"})
		if err != nil || sources != nil || disabled != 0 {
			t.Fatalf("ReadSources(%q) = %v, %d, %v; want nil, 0, nil", dir, sources, disabled, err)
		}
	}
}

func TestReadSourcesRefusesUnsafeRulesDir(t *testing.T) {
	dir := writeRulesDir(t, map[string]string{"a.yar": "rule a { condition: true }"})
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ReadSources(dir, nil); err == nil {
		t.Fatal("a world-writable rules dir must be refused")
	}
}
