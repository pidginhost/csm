package modsec

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWriteAndReadOverrides(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "overrides.conf")

	disabled := []int{900112, 900008, 900003}
	if err := WriteOverrides(path, disabled); err != nil {
		t.Fatalf("WriteOverrides: %v", err)
	}

	// Verify file content
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)
	if !strings.Contains(content, "SecRuleRemoveById 900003") {
		t.Error("missing SecRuleRemoveById 900003")
	}
	if !strings.Contains(content, "SecRuleRemoveById 900112") {
		t.Error("missing SecRuleRemoveById 900112")
	}

	// Read back
	ids, err := ReadOverrides(path)
	if err != nil {
		t.Fatalf("ReadOverrides: %v", err)
	}
	if len(ids) != 3 {
		t.Fatalf("expected 3 disabled IDs, got %d", len(ids))
	}
}

func TestReadOverridesEmpty(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "overrides.conf")

	// Empty file
	if err := WriteOverrides(path, nil); err != nil {
		t.Fatal(err)
	}

	ids, err := ReadOverrides(path)
	if err != nil {
		t.Fatalf("ReadOverrides: %v", err)
	}
	if len(ids) != 0 {
		t.Errorf("expected 0 disabled IDs, got %d", len(ids))
	}
}

func TestReadOverridesNotFound(t *testing.T) {
	ids, err := ReadOverrides("/nonexistent/path")
	if err != nil {
		t.Fatalf("should not error on missing file: %v", err)
	}
	if len(ids) != 0 {
		t.Error("expected empty list for missing file")
	}
}

func TestRollbackOverrides(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "overrides.conf")

	// Write initial state
	if err := WriteOverrides(path, []int{900001}); err != nil {
		t.Fatal(err)
	}

	// Save for rollback
	original := ReadOverridesRaw(path)

	// Overwrite
	if err := WriteOverrides(path, []int{900001, 900003, 900007}); err != nil {
		t.Fatal(err)
	}

	// Rollback
	if err := RestoreOverrides(path, original); err != nil {
		t.Fatalf("RestoreOverrides: %v", err)
	}

	// Verify rollback
	ids, _ := ReadOverrides(path)
	if len(ids) != 1 || ids[0] != 900001 {
		t.Errorf("after rollback: got %v, want [900001]", ids)
	}
}
