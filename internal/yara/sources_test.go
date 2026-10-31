package yara

import (
	"os"
	"path/filepath"
	"reflect"
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
		"c.YAR":  "rule c { condition: true }",
		"d.YaRa": "rule d { condition: true }",
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
	if strings.Join(names, ",") != "a.yar,b.yara,c.YAR,d.YaRa" {
		t.Fatalf("names = %v, want [a.yar b.yara c.YAR d.YaRa]", names)
	}
}

func TestReadSourcesPreservesFilteredTextAndCounts(t *testing.T) {
	const keep = "// retained comment\nrule keep { condition: true }\n"
	const builtin = "rule ELCEEF_HTML_Smuggling_A { condition: true }"
	const operator = "global private rule drop { condition: true }"
	dir := writeRulesDir(t, map[string]string{
		"a.yar":  builtin + "\n" + keep + operator + "\n",
		"b.yara": operator,
		"c.yar":  "// no declarations\n",
	})
	sources, disabled, err := ReadSources(dir, []string{"", " drop ", "DROP", "drop", "ELCEEF_HTML_Smuggling_A", "unknown"})
	if err != nil {
		t.Fatal(err)
	}
	want := []Source{
		{Name: "a.yar", Text: []byte("\n" + keep + "\n")},
		{Name: "b.yara", Text: []byte{}},
		{Name: "c.yar", Text: []byte("// no declarations\n")},
	}
	if disabled != 3 {
		t.Fatalf("disabled count = %d, want 3 declarations", disabled)
	}
	if len(sources) != len(want) {
		t.Fatalf("got %d sources, want %d", len(sources), len(want))
	}
	for i, src := range sources {
		if src.Name != want[i].Name || string(src.Text) != string(want[i].Text) {
			t.Errorf("source %d = %q, %q; want %q, %q", i, src.Name, src.Text, want[i].Name, want[i].Text)
		}
	}
}

func TestReadSourcesRefusesUnsafeRuleFiles(t *testing.T) {
	for _, kind := range []string{"writable", "symlink"} {
		t.Run(kind, func(t *testing.T) {
			dir := writeRulesDir(t, map[string]string{"a.yar": "rule a { condition: true }"})
			path := filepath.Join(dir, "a.yar")
			if kind == "writable" {
				if err := os.Chmod(path, 0o660); err != nil {
					t.Fatal(err)
				}
			} else if err := os.Symlink(path, filepath.Join(dir, "b.YaRa")); err != nil {
				t.Fatal(err)
			}
			sources, disabled, err := ReadSources(dir, nil)
			if err == nil || sources != nil || disabled != 0 {
				t.Fatalf("unsafe sources = %v, %d, %v; want nil, 0, error", sources, disabled, err)
			}
		})
	}
}

func TestReadSourcesLeavesDisabledNamesUnchanged(t *testing.T) {
	dir := writeRulesDir(t, map[string]string{"a.yar": "rule drop { condition: true }"})
	disabled := []string{" drop ", "", "drop"}
	want := append([]string(nil), disabled...)
	if _, _, err := ReadSources(dir, disabled); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(disabled, want) {
		t.Fatalf("disabled names changed to %q, want %q", disabled, want)
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
