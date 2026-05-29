package checks

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

type fakeQuarantineFileInfo struct {
	name string
	size int64
	mode os.FileMode
	mod  time.Time
	sys  any
}

func (f fakeQuarantineFileInfo) Name() string       { return f.name }
func (f fakeQuarantineFileInfo) Size() int64        { return f.size }
func (f fakeQuarantineFileInfo) Mode() os.FileMode  { return f.mode }
func (f fakeQuarantineFileInfo) ModTime() time.Time { return f.mod }
func (f fakeQuarantineFileInfo) IsDir() bool        { return f.mode.IsDir() }
func (f fakeQuarantineFileInfo) Sys() any           { return f.sys }

func TestRemoveQuarantinedSourceRejectsChangedSameInodeSource(t *testing.T) {
	tmp := t.TempDir()
	src := filepath.Join(tmp, "drop.php")
	qPath := filepath.Join(tmp, "q", "drop.php")
	if err := os.WriteFile(src, []byte("replacement"), 0o644); err != nil {
		t.Fatalf("write source: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(qPath), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(qPath, []byte("quarantined"), 0o600); err != nil {
		t.Fatalf("write quarantine copy: %v", err)
	}
	info, err := os.Lstat(src)
	if err != nil {
		t.Fatalf("lstat: %v", err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Skip("stat_t unavailable")
	}

	original := fakeQuarantineFileInfo{
		name: info.Name(),
		size: info.Size() + 1,
		mode: info.Mode(),
		mod:  info.ModTime().Add(-time.Second),
		sys:  &syscall.Stat_t{Dev: stat.Dev, Ino: stat.Ino},
	}
	if err := removeQuarantinedSource(src, qPath, original); err == nil {
		t.Fatal("expected source shape change to fail closed")
	}
	if _, err := os.Stat(src); err != nil {
		t.Fatalf("changed source should be left in place: %v", err)
	}
	if _, err := os.Stat(qPath); !os.IsNotExist(err) {
		t.Fatalf("quarantine copy should be removed after failure, err=%v", err)
	}
}
