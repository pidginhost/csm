package emailav

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
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

func TestMoveFileCrossDeviceFallbackUsesOpenedSource(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src.txt")
	dst := filepath.Join(dir, "dst.txt")
	original := []byte("original")
	if err := os.WriteFile(src, original, 0600); err != nil {
		t.Fatalf("write source: %v", err)
	}
	forceMoveFileEXDEV(t)

	if err := moveFile(src, dst); err != nil {
		t.Fatalf("moveFile: %v", err)
	}
	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatalf("read dst: %v", err)
	}
	if string(got) != string(original) {
		t.Fatalf("dst content = %q, want %q", got, original)
	}
	if _, err := os.Stat(src); !os.IsNotExist(err) {
		t.Fatalf("src should be removed after cross-device move, got %v", err)
	}
}

func TestMoveFileCrossDeviceRefusesSymlinkSource(t *testing.T) {
	dir := t.TempDir()
	victim := filepath.Join(dir, "victim.txt")
	src := filepath.Join(dir, "src.txt")
	dst := filepath.Join(dir, "dst.txt")
	if err := os.WriteFile(victim, []byte("important"), 0600); err != nil {
		t.Fatalf("write victim: %v", err)
	}
	if err := os.Symlink(victim, src); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	forceMoveFileEXDEV(t)

	if err := moveFile(src, dst); err == nil {
		t.Fatal("moveFile should reject symlink source in cross-device fallback")
	}
	if _, err := os.Stat(dst); !os.IsNotExist(err) {
		t.Fatalf("dst should not be created for symlink source, got %v", err)
	}
	if _, err := os.Stat(victim); err != nil {
		t.Fatalf("victim should remain in place: %v", err)
	}
}

func TestMoveFileCrossDeviceRejectsSourceSwapAfterCopy(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src.txt")
	dst := filepath.Join(dir, "dst.txt")
	if err := os.WriteFile(src, []byte("original"), 0600); err != nil {
		t.Fatalf("write source: %v", err)
	}
	forceMoveFileEXDEV(t)

	oldHook := moveFileAfterCrossDeviceCopy
	moveFileAfterCrossDeviceCopy = func(_, _ string) error {
		if err := os.Remove(src); err != nil {
			return err
		}
		return os.WriteFile(src, []byte("replacement"), 0600)
	}
	t.Cleanup(func() { moveFileAfterCrossDeviceCopy = oldHook })

	err := moveFile(src, dst)
	if err == nil {
		t.Fatal("moveFile should reject a source path swap after copy")
	}
	if !strings.Contains(err.Error(), "changed during copy") {
		t.Fatalf("moveFile error = %v, want changed during copy", err)
	}
	if _, statErr := os.Stat(dst); !os.IsNotExist(statErr) {
		t.Fatalf("dst should be removed after source swap rejection, got %v", statErr)
	}
	got, err := os.ReadFile(src)
	if err != nil {
		t.Fatalf("replacement source should remain: %v", err)
	}
	if string(got) != "replacement" {
		t.Fatalf("source content = %q, want replacement", got)
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

func forceMoveFileEXDEV(t *testing.T) {
	t.Helper()
	oldRename := moveFileRename
	moveFileRename = func(src, dst string) error {
		return &os.LinkError{Op: "rename", Old: src, New: dst, Err: syscall.EXDEV}
	}
	t.Cleanup(func() { moveFileRename = oldRename })
}
