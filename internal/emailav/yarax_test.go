//go:build yara

package emailav

import (
	"os"
	"path/filepath"
	"testing"

	yara_x "github.com/VirusTotal/yara-x/go"
)

func compileTestRules(t *testing.T, source string) *yara_x.Rules {
	t.Helper()
	compiler, err := yara_x.NewCompiler()
	if err != nil {
		t.Fatalf("creating compiler: %v", err)
	}
	if err := compiler.AddSource(source); err != nil {
		t.Fatalf("adding source: %v", err)
	}
	return compiler.Build()
}

func TestYaraXScannerClean(t *testing.T) {
	rules := compileTestRules(t, `
rule test_malware {
    meta:
        severity = "critical"
    strings:
        $s1 = "MALWARE_SIGNATURE_XYZ"
    condition:
        $s1
}`)

	scanner := NewYaraXScanner(rules)
	if scanner.Name() != "yara-x" {
		t.Errorf("Name() = %q, want %q", scanner.Name(), "yara-x")
	}
	if !scanner.Available() {
		t.Error("scanner with compiled rules should be available")
	}

	tmpFile := filepath.Join(t.TempDir(), "clean.txt")
	os.WriteFile(tmpFile, []byte("this is clean content"), 0644)

	verdict, err := scanner.Scan(tmpFile)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if verdict.Infected {
		t.Error("clean file should not be infected")
	}
}

func TestYaraXScannerInfectedWithSeverity(t *testing.T) {
	rules := compileTestRules(t, `
rule test_malware {
    meta:
        severity = "critical"
    strings:
        $s1 = "MALWARE_SIGNATURE_XYZ"
    condition:
        $s1
}`)

	scanner := NewYaraXScanner(rules)

	tmpFile := filepath.Join(t.TempDir(), "malware.bin")
	os.WriteFile(tmpFile, []byte("contains MALWARE_SIGNATURE_XYZ here"), 0644)

	verdict, err := scanner.Scan(tmpFile)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if !verdict.Infected {
		t.Error("file matching rule should be infected")
	}
	if verdict.Signature != "test_malware" {
		t.Errorf("Signature = %q, want %q", verdict.Signature, "test_malware")
	}
	if verdict.Severity != "critical" {
		t.Errorf("Severity = %q, want %q", verdict.Severity, "critical")
	}
}

func TestYaraXScannerDefaultSeverity(t *testing.T) {
	rules := compileTestRules(t, `
rule test_noseverity {
    strings:
        $s1 = "NOSEV_MARKER"
    condition:
        $s1
}`)

	scanner := NewYaraXScanner(rules)

	tmpFile := filepath.Join(t.TempDir(), "nosev.bin")
	os.WriteFile(tmpFile, []byte("contains NOSEV_MARKER here"), 0644)

	verdict, err := scanner.Scan(tmpFile)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if !verdict.Infected {
		t.Error("file should match rule")
	}
	if verdict.Severity != "high" {
		t.Errorf("Severity = %q, want %q (default)", verdict.Severity, "high")
	}
}

func TestYaraXScannerNilRules(t *testing.T) {
	scanner := NewYaraXScanner(nil)
	if scanner.Available() {
		t.Error("scanner with nil rules should not be available")
	}
}

type reloadingRulesSupplier struct {
	rules *yara_x.Rules
}

func (s *reloadingRulesSupplier) GlobalRules() *yara_x.Rules {
	return s.rules
}

func TestYaraXScannerUsesReloadedRules(t *testing.T) {
	supplier := &reloadingRulesSupplier{
		rules: compileTestRules(t, `
rule original_rule {
    strings:
        $s1 = "FIRST_SIGNATURE"
    condition:
        $s1
}`),
	}
	scanner := NewYaraXScanner(supplier)

	tmpFile := filepath.Join(t.TempDir(), "reload.bin")
	os.WriteFile(tmpFile, []byte("contains FIRST_SIGNATURE here"), 0644)

	verdict, err := scanner.Scan(tmpFile)
	if err != nil {
		t.Fatalf("Scan before reload: %v", err)
	}
	if verdict.Signature != "original_rule" {
		t.Fatalf("Signature before reload = %q, want %q", verdict.Signature, "original_rule")
	}

	supplier.rules = compileTestRules(t, `
rule reloaded_rule {
    strings:
        $s1 = "SECOND_SIGNATURE"
    condition:
        $s1
}`)
	if err := os.WriteFile(tmpFile, []byte("contains SECOND_SIGNATURE here"), 0644); err != nil {
		t.Fatalf("updating test file: %v", err)
	}

	verdict, err = scanner.Scan(tmpFile)
	if err != nil {
		t.Fatalf("Scan after reload: %v", err)
	}
	if verdict.Signature != "reloaded_rule" {
		t.Errorf("Signature after reload = %q, want %q", verdict.Signature, "reloaded_rule")
	}
}
