//go:build yara

package yara

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReloadRejectsInvalidRulesAndPreservesExistingSet(t *testing.T) {
	dir := t.TempDir()
	validRule := `rule good_rule { condition: true }`
	rulePath := filepath.Join(dir, "test.yar")
	if err := os.WriteFile(rulePath, []byte(validRule), 0644); err != nil {
		t.Fatal(err)
	}

	scanner, err := NewScanner(dir)
	if err != nil {
		t.Fatalf("initial load failed: %v", err)
	}
	if scanner.RuleCount() != 1 {
		t.Fatalf("initial rule count = %d, want 1", scanner.RuleCount())
	}

	invalidRule := `rule broken_rule { condition:`
	if err := os.WriteFile(rulePath, []byte(invalidRule), 0644); err != nil {
		t.Fatal(err)
	}

	if err := scanner.Reload(); err == nil {
		t.Fatal("expected reload error for invalid yara source")
	}
	if scanner.RuleCount() != 1 {
		t.Fatalf("rule count after failed reload = %d, want 1", scanner.RuleCount())
	}
	if matches, err := scanner.ScanBytesChecked([]byte("probe")); err != nil || len(matches) != 1 || matches[0].RuleName != "good_rule" {
		t.Fatalf("scan after failed reload = %v, %v; want good_rule", matches, err)
	}
}

func TestReloadEmptyInputsPreserveExistingSet(t *testing.T) {
	for _, tc := range []struct {
		name    string
		change  func(string) error
		wantErr string
	}{
		{name: "missing directory", change: func(dir string) error { return os.Rename(dir, dir+"-moved") }},
		{name: "no rule files", change: func(dir string) error {
			return os.Rename(filepath.Join(dir, "test.yar"), filepath.Join(dir, "test.txt"))
		}, wantErr: "no YARA rule files"},
		{name: "zero rules", change: func(dir string) error {
			return os.WriteFile(filepath.Join(dir, "test.yar"), []byte("// no rules\n"), 0o600)
		}, wantErr: "no YARA rules compiled"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := writeRulesDir(t, map[string]string{"test.yar": "rule keep { condition: true } rule drop { condition: true }"})
			scanner, err := NewScanner(dir, "drop")
			if err != nil {
				t.Fatal(err)
			}
			if changeErr := tc.change(dir); changeErr != nil {
				t.Fatal(changeErr)
			}
			err = scanner.Reload()
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("Reload = %v, want nil", err)
				}
			} else if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("Reload = %v, want %q", err, tc.wantErr)
			}
			if scanner.RuleCount() != 1 || scanner.DisabledRuleCount() != 1 {
				t.Fatalf("counts = %d enabled, %d disabled; want 1 each", scanner.RuleCount(), scanner.DisabledRuleCount())
			}
			matches, err := scanner.ScanBytesChecked([]byte("probe"))
			if err != nil || len(matches) != 1 || matches[0].RuleName != "keep" {
				t.Fatalf("scan = %v, %v; want keep", matches, err)
			}
		})
	}
}

func TestNewScannerEmptyInputs(t *testing.T) {
	for _, tc := range []struct {
		name    string
		files   map[string]string
		wantErr bool
	}{
		{name: "no rule files"},
		{name: "zero rules", files: map[string]string{"test.yar": "// no rules\n"}, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			scanner, err := NewScanner(writeRulesDir(t, tc.files), "absent_rule")
			if (err != nil) != tc.wantErr {
				t.Fatalf("NewScanner error = %v, want error %t", err, tc.wantErr)
			}
			if !tc.wantErr && (scanner.RuleCount() != 0 || scanner.DisabledRuleCount() != 0) {
				t.Fatal("empty directory must have no enabled or disabled rules")
			}
		})
	}
}
