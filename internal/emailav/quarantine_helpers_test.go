package emailav

import (
	"os"
	"path/filepath"
	"testing"
)

// --- moveFile ---------------------------------------------------------

func TestMoveFileSameDevice(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src.txt")
	dst := filepath.Join(dir, "dst.txt")
	_ = os.WriteFile(src, []byte("hello"), 0600)

	if err := moveFile(src, dst); err != nil {
		t.Fatalf("moveFile: %v", err)
	}
	data, err := os.ReadFile(dst)
	if err != nil {
		t.Fatalf("dst not readable: %v", err)
	}
	if string(data) != "hello" {
		t.Errorf("dst content = %q", data)
	}
	if _, err := os.Stat(src); !os.IsNotExist(err) {
		t.Error("src should be removed after move")
	}
}

func TestMoveFileMissingSrc(t *testing.T) {
	dir := t.TempDir()
	err := moveFile(filepath.Join(dir, "nope"), filepath.Join(dir, "dst"))
	if err == nil {
		t.Error("missing src should return error")
	}
}

// --- rollbackMovedFiles -----------------------------------------------

func TestRollbackMovedFiles(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "a.txt")
	b := filepath.Join(dir, "b.txt")
	_ = os.WriteFile(b, []byte("moved"), 0600)

	moved := []movedFile{{src: a, dst: b}}
	if err := rollbackMovedFiles(moved); err != nil {
		t.Fatalf("rollback: %v", err)
	}
	if _, err := os.Stat(a); err != nil {
		t.Error("rollback should restore src")
	}
}

func TestRollbackMovedFilesEmpty(t *testing.T) {
	if err := rollbackMovedFiles(nil); err != nil {
		t.Fatalf("empty rollback: %v", err)
	}
}
