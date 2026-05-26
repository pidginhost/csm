package yara

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateRulesDir_AcceptsSafeLayout(t *testing.T) {
	tmp := t.TempDir()
	dir := filepath.Join(tmp, "rules")
	if err := os.Mkdir(dir, 0750); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "ok.yar"), []byte("rule x { condition: true }"), 0640); err != nil {
		t.Fatalf("write rule: %v", err)
	}

	if err := validateRulesDir(dir); err != nil {
		t.Errorf("safe dir should pass, got %v", err)
	}
}

func TestValidateRulesDir_RejectsWorldWritableDir(t *testing.T) {
	tmp := t.TempDir()
	dir := filepath.Join(tmp, "rules")
	if err := os.Mkdir(dir, 0750); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.Chmod(dir, 0777); err != nil {
		t.Fatalf("chmod: %v", err)
	}

	err := validateRulesDir(dir)
	if err == nil {
		t.Fatal("world-writable rules dir must be rejected")
	}
	if !strings.Contains(err.Error(), "writable") {
		t.Errorf("error should mention writable, got %v", err)
	}
}

func TestValidateRulesDir_RejectsGroupWritableRuleFile(t *testing.T) {
	tmp := t.TempDir()
	dir := filepath.Join(tmp, "rules")
	if err := os.Mkdir(dir, 0750); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	rule := filepath.Join(dir, "bad.yar")
	if err := os.WriteFile(rule, []byte("rule x { condition: true }"), 0640); err != nil {
		t.Fatalf("write rule: %v", err)
	}
	if err := os.Chmod(rule, 0660); err != nil {
		t.Fatalf("chmod: %v", err)
	}

	err := validateRulesDir(dir)
	if err == nil {
		t.Fatal("group-writable rule file must be rejected")
	}
}

func TestValidateRulesDir_AcceptsMissingDir(t *testing.T) {
	// Missing rules dir is a recoverable state (operator deferred YARA
	// install); Reload already treats it as nil. Validation must not
	// fail-startup on it either.
	tmp := t.TempDir()
	missing := filepath.Join(tmp, "absent")
	if err := validateRulesDir(missing); err != nil {
		t.Errorf("missing dir should be a no-op, got %v", err)
	}
}

func TestValidateRulesDir_RejectsRegularFileAsDir(t *testing.T) {
	tmp := t.TempDir()
	file := filepath.Join(tmp, "not-a-dir")
	if err := os.WriteFile(file, []byte("x"), 0640); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := validateRulesDir(file); err == nil {
		t.Fatal("regular file masquerading as rules dir must be rejected")
	}
}
