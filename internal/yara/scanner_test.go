//go:build yara

package yara

import (
	"path/filepath"
	"runtime"
	"testing"
)

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
}

func hasYaraRule(matches []Match, ruleName string) bool {
	for _, m := range matches {
		if m.RuleName == ruleName {
			return true
		}
	}
	return false
}
