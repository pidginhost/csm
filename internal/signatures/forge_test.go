package signatures

import (
	"archive/zip"
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A compromised CDN or signing key could serve a small ZIP whose .yar entry
// decompresses to gigabytes (a zip bomb). forgeExtractYar must cap the
// decompressed read so installing rules cannot OOM the daemon.
func TestForgeExtractYarCapsDecompressedSize(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create("rules.yar")
	if err != nil {
		t.Fatal(err)
	}
	chunk := bytes.Repeat([]byte("A"), 32*1024)
	for remaining := forgeMaxYarSize + 1024*1024; remaining > 0; {
		n := len(chunk)
		if remaining < n {
			n = remaining
		}
		if _, err := w.Write(chunk[:n]); err != nil {
			t.Fatal(err)
		}
		remaining -= n
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}

	if _, err := forgeExtractYar(buf.Bytes(), "rules.yar"); err == nil {
		t.Fatal("forgeExtractYar must reject a .yar entry exceeding the decompressed cap")
	}
}

func TestForgeExtractYarAcceptsNormalEntry(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create("rules.yar")
	if err != nil {
		t.Fatal(err)
	}
	body := []byte("rule x { condition: true }\n")
	if _, werr := w.Write(body); werr != nil {
		t.Fatal(werr)
	}
	if cerr := zw.Close(); cerr != nil {
		t.Fatal(cerr)
	}

	got, err := forgeExtractYar(buf.Bytes(), "rules.yar")
	if err != nil {
		t.Fatalf("forgeExtractYar: %v", err)
	}
	if !bytes.Equal(got, body) {
		t.Fatalf("got %q, want %q", got, body)
	}
}

func TestForgeUpdateCreatesRulesDir(t *testing.T) {
	pubHex, priv := genSigningKey(t)
	zipData := buildForgeZip(t)

	swapDefaultTransport(t, &forgeRoundTripper{
		releases: []byte(`{"tag_name":"v2026.04.11"}`),
		zipBody:  zipData,
		sigBody:  sign(priv, zipData),
	})

	rulesDir := filepath.Join(t.TempDir(), "missing", "rules")
	if _, _, err := ForgeUpdateFromURL(rulesDir, "core", "v2026.01.01", pubHex, "https://mirror.example/yara-forge-rules-{tier}.zip", nil); err != nil {
		t.Fatalf("ForgeUpdate: %v", err)
	}
	if _, err := os.Stat(filepath.Join(rulesDir, "yara-forge-core.yar")); err != nil {
		t.Fatalf("installed file missing: %v", err)
	}
}

func TestForgeUpdateKeepsExistingTierWhenInstallFails(t *testing.T) {
	pubHex, priv := genSigningKey(t)
	zipData := buildForgeZip(t)

	swapDefaultTransport(t, &forgeRoundTripper{
		releases: []byte(`{"tag_name":"v2026.04.11"}`),
		zipBody:  zipData,
		sigBody:  sign(priv, zipData),
	})

	rulesDir := t.TempDir()
	oldTier := filepath.Join(rulesDir, "yara-forge-extended.yar")
	if err := os.WriteFile(oldTier, []byte("rule old_tier { condition: true }\n"), 0600); err != nil {
		t.Fatal(err)
	}

	prev := forgeAtomicWrite
	forgeAtomicWrite = func(string, os.FileMode, []byte) error {
		return errors.New("disk full")
	}
	t.Cleanup(func() { forgeAtomicWrite = prev })

	_, _, err := ForgeUpdateFromURL(rulesDir, "core", "v2026.01.01", pubHex, "https://mirror.example/yara-forge-rules-{tier}.zip", nil)
	if err == nil || !strings.Contains(err.Error(), "installing rules") {
		t.Fatalf("err = %v, want installing rules", err)
	}
	if _, statErr := os.Stat(oldTier); statErr != nil {
		t.Fatalf("existing tier was not preserved: %v", statErr)
	}
	if _, statErr := os.Stat(filepath.Join(rulesDir, "yara-forge-core.yar")); !os.IsNotExist(statErr) {
		t.Fatalf("new tier should not exist after failed install, stat err=%v", statErr)
	}
}

func TestForgeUpdateRemovesInactiveTierAfterInstall(t *testing.T) {
	pubHex, priv := genSigningKey(t)
	zipData := buildForgeZip(t)

	swapDefaultTransport(t, &forgeRoundTripper{
		releases: []byte(`{"tag_name":"v2026.04.11"}`),
		zipBody:  zipData,
		sigBody:  sign(priv, zipData),
	})

	rulesDir := t.TempDir()
	oldTier := filepath.Join(rulesDir, "yara-forge-extended.yar")
	if err := os.WriteFile(oldTier, []byte("rule old_tier { condition: true }\n"), 0600); err != nil {
		t.Fatal(err)
	}

	if _, _, err := ForgeUpdateFromURL(rulesDir, "core", "v2026.01.01", pubHex, "https://mirror.example/yara-forge-rules-{tier}.zip", nil); err != nil {
		t.Fatalf("ForgeUpdate: %v", err)
	}
	if _, err := os.Stat(oldTier); !os.IsNotExist(err) {
		t.Fatalf("inactive tier should be removed after successful install, stat err=%v", err)
	}
	if _, err := os.Stat(filepath.Join(rulesDir, "yara-forge-core.yar")); err != nil {
		t.Fatalf("new tier missing: %v", err)
	}
}

func TestForgeUpdateCleanupFailureKeepsNewTier(t *testing.T) {
	pubHex, priv := genSigningKey(t)
	zipData := buildForgeZip(t)

	swapDefaultTransport(t, &forgeRoundTripper{
		releases: []byte(`{"tag_name":"v2026.04.11"}`),
		zipBody:  zipData,
		sigBody:  sign(priv, zipData),
	})

	rulesDir := t.TempDir()
	staleTier := filepath.Join(rulesDir, "yara-forge-extended.yar")
	if err := os.Mkdir(staleTier, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(staleTier, "child"), []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}

	_, _, err := ForgeUpdateFromURL(rulesDir, "core", "v2026.01.01", pubHex, "https://mirror.example/yara-forge-rules-{tier}.zip", nil)
	if err == nil || !strings.Contains(err.Error(), "removing inactive Forge tier extended") {
		t.Fatalf("err = %v, want inactive tier removal failure", err)
	}
	if _, statErr := os.Stat(filepath.Join(rulesDir, "yara-forge-core.yar")); statErr != nil {
		t.Fatalf("new tier should remain after cleanup failure: %v", statErr)
	}
}

func TestForgeUpdateSameTierCleanupFailureKeepsExistingRules(t *testing.T) {
	pubHex, priv := genSigningKey(t)
	zipData := buildForgeZip(t)

	swapDefaultTransport(t, &forgeRoundTripper{
		releases: []byte(`{"tag_name":"v2026.04.11"}`),
		zipBody:  zipData,
		sigBody:  sign(priv, zipData),
	})

	rulesDir := t.TempDir()
	active := filepath.Join(rulesDir, "yara-forge-core.yar")
	oldRules := []byte("rule old_core { condition: true }\n")
	if err := os.WriteFile(active, oldRules, 0600); err != nil {
		t.Fatal(err)
	}
	staleTier := filepath.Join(rulesDir, "yara-forge-extended.yar")
	if err := os.Mkdir(staleTier, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(staleTier, "child"), []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}

	_, _, err := ForgeUpdateFromURL(rulesDir, "core", "v2026.01.01", pubHex, "https://mirror.example/yara-forge-rules-{tier}.zip", nil)
	if err == nil || !strings.Contains(err.Error(), "removing inactive Forge tier extended") {
		t.Fatalf("err = %v, want inactive tier removal failure", err)
	}
	got, readErr := os.ReadFile(active)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if !bytes.Equal(got, oldRules) {
		t.Fatalf("active rules changed after failed cleanup: got %q, want %q", got, oldRules)
	}
}

func TestExtractRuleName(t *testing.T) {
	tests := []struct {
		line string
		want string
	}{
		{"rule SUSP_XOR_Encoded {", "SUSP_XOR_Encoded"},
		{"private rule PRIV_Helper {", "PRIV_Helper"},
		{"rule Webshell_PHP : webshell {", "Webshell_PHP"},
		{"rule NoOpenBrace", "NoOpenBrace"},
		{"not a rule", ""},
		{"", ""},
		{"ruler of the world", ""},
	}
	for _, tt := range tests {
		got := extractRuleName(tt.line)
		if got != tt.want {
			t.Errorf("extractRuleName(%q) = %q, want %q", tt.line, got, tt.want)
		}
	}
}

func TestFilterDisabledRules(t *testing.T) {
	input := []byte("// header comment\nrule Keep_This {\n    strings:\n        $a = \"safe\"\n    condition:\n        $a\n}\n\nrule Remove_Me {\n    strings:\n        $b = \"bad\"\n    condition:\n        $b\n}\n\nrule Also_Keep {\n    condition:\n        true\n}\n")
	disabled := []string{"Remove_Me"}
	result := filterDisabledRules(input, disabled)
	resultStr := string(result)

	if !strings.Contains(resultStr, "Keep_This") {
		t.Error("Keep_This should be preserved")
	}
	if strings.Contains(resultStr, "Remove_Me") {
		t.Error("Remove_Me should be filtered out")
	}
	if !strings.Contains(resultStr, "Also_Keep") {
		t.Error("Also_Keep should be preserved")
	}
}

func TestFilterDisabledRulesPrivate(t *testing.T) {
	input := []byte("private rule Helper {\n    condition:\n        true\n}\n\nrule Main_Rule {\n    condition:\n        Helper\n}\n")
	disabled := []string{"Helper"}
	result := filterDisabledRules(input, disabled)
	resultStr := string(result)

	if strings.Contains(resultStr, "private rule Helper") {
		t.Error("private rule Helper declaration should be filtered out")
	}
	if !strings.Contains(resultStr, "Main_Rule") {
		t.Error("Main_Rule should be preserved")
	}
}

func TestFilterDisabledRulesEmpty(t *testing.T) {
	input := []byte("rule Foo { condition: true }")
	result := filterDisabledRules(input, nil)
	if string(result) != string(input) {
		t.Error("empty disabled list should return input unchanged")
	}
}

func TestCountRules(t *testing.T) {
	input := []byte("rule A { condition: true }\nrule B { condition: true }\nprivate rule C { condition: true }\n// not a rule\n")
	got := countRules(input)
	if got != 3 {
		t.Errorf("countRules() = %d, want 3", got)
	}
}
