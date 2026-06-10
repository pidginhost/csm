package signatures

import (
	"archive/zip"
	"bytes"
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
	// Highly compressible payload far larger than the cap.
	big := bytes.Repeat([]byte("A"), forgeMaxYarSize+1024*1024)
	if _, err := w.Write(big); err != nil {
		t.Fatal(err)
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
