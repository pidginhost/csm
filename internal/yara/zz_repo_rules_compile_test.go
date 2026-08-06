//go:build yara

package yara

import (
	"os"
	"path/filepath"
	"testing"
)

// The shipped .yar must compile under YARA-X, not just parse by eye.
func TestRepositoryYaraRulesCompile(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "configs", "malware.yar"))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "malware.yar"), data, 0o644); err != nil {
		t.Fatal(err)
	}
	s, err := NewScanner(dir)
	if err != nil {
		t.Fatalf("configs/malware.yar failed to compile: %v", err)
	}
	_ = s
}
