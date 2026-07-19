//go:build yara

package yara

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestScannerScanFileCheckedSurfacesPathErrors(t *testing.T) {
	scanner := loadRepoYaraScanner(t)
	if _, err := scanner.ScanFileChecked(filepath.Join(t.TempDir(), "missing.php"), 1024); err == nil {
		t.Fatal("missing path must return an error")
	}

	path := filepath.Join(t.TempDir(), "large.php")
	if err := os.WriteFile(path, []byte("payload"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := scanner.ScanFileChecked(path, 3); err == nil {
		t.Fatal("file beyond maxBytes must return an error")
	}
}

func TestScannerScanFileCheckedHashesScannedBytes(t *testing.T) {
	scanner := loadRepoYaraScanner(t)
	content := []byte("clean file content")
	path := filepath.Join(t.TempDir(), "clean.php")
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}

	result, err := scanner.ScanFileChecked(path, 1024)
	if err != nil {
		t.Fatal(err)
	}
	want := fmt.Sprintf("%x", sha256.Sum256(content))
	if result.ContentSHA256 != want {
		t.Fatalf("content hash = %q, want %q", result.ContentSHA256, want)
	}
}

func TestScannerScanFileCheckedAcceptsMaximumIntLimit(t *testing.T) {
	scanner := loadRepoYaraScanner(t)
	path := filepath.Join(t.TempDir(), "clean.php")
	if err := os.WriteFile(path, []byte("clean"), 0o600); err != nil {
		t.Fatal(err)
	}

	maxInt := int(^uint(0) >> 1)
	if _, err := scanner.ScanFileChecked(path, maxInt); err != nil {
		t.Fatalf("maximum int limit must not overflow: %v", err)
	}
}

func TestScannerScanFileRetainsPrefixScanCompatibility(t *testing.T) {
	scanner := loadRepoYaraScanner(t)
	payload := []byte(`<?php passthru($_GET['cmd']);`)
	path := filepath.Join(t.TempDir(), "padded.php")
	if err := os.WriteFile(path, append(payload, []byte(" harmless padding")...), 0o600); err != nil {
		t.Fatal(err)
	}

	if matches := scanner.ScanFile(path, len(payload)); len(matches) == 0 {
		t.Fatal("legacy ScanFile must continue scanning the bounded prefix")
	}
}

func TestRepoHtaccessAutoPrependRuleCatchesSuspiciousTargets(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	configsDir := filepath.Join(filepath.Dir(thisFile), "..", "..", "configs")
	scanner, err := NewScanner(configsDir)
	if err != nil {
		t.Fatalf("loading repo YARA rules: %v", err)
	}
	if scanner == nil || scanner.RuleCount() == 0 {
		t.Fatal("expected YARA rules to load")
	}

	suspicious := []byte("php_value auto_prepend_file /home/user/public_html/.cache/.x.php\n")
	if !hasYaraRule(scanner.ScanBytes(suspicious), "backdoor_htaccess_auto_prepend") {
		t.Fatal("expected suspicious auto_prepend_file target to match")
	}

	adminVariant := []byte("php_admin_value auto_prepend_file /home/user/public_html/.cache/.x.php\n")
	if !hasYaraRule(scanner.ScanBytes(adminVariant), "backdoor_htaccess_auto_prepend") {
		t.Fatal("expected php_admin_value auto_prepend_file target to match")
	}
}

func TestRepoHtaccessAutoPrependRuleAllowsKnownLegitimateTargets(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	configsDir := filepath.Join(filepath.Dir(thisFile), "..", "..", "configs")
	scanner, err := NewScanner(configsDir)
	if err != nil {
		t.Fatalf("loading repo YARA rules: %v", err)
	}
	if scanner == nil || scanner.RuleCount() == 0 {
		t.Fatal("expected YARA rules to load")
	}

	legitimate := []byte("php_value auto_prepend_file /home/user/public_html/wordfence-waf.php\n")
	if hasYaraRule(scanner.ScanBytes(legitimate), "backdoor_htaccess_auto_prepend") {
		t.Fatal("expected wordfence auto_prepend_file target to stay excluded")
	}

	adminVariant := []byte("php_admin_value auto_prepend_file /home/user/public_html/wordfence-waf.php\n")
	if hasYaraRule(scanner.ScanBytes(adminVariant), "backdoor_htaccess_auto_prepend") {
		t.Fatal("expected php_admin_value wordfence auto_prepend_file target to stay excluded")
	}
}

func hasYaraRule(matches []Match, ruleName string) bool {
	for _, m := range matches {
		if m.RuleName == ruleName {
			return true
		}
	}
	return false
}
