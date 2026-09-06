//go:build linux

package emailav

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestCrossDeviceSpoolMovePreservesOriginalAttributes(t *testing.T) {
	source, destination := filepath.Join(t.TempDir(), "message-D"), filepath.Join(t.TempDir(), "message-D")
	if err := os.WriteFile(source, []byte("message body"), 0640); err != nil {
		t.Fatal(err)
	}
	if os.Geteuid() == 0 {
		if err := os.Chown(source, 1001, 1002); err != nil {
			t.Fatal(err)
		}
	}
	stamp := time.Date(2024, 2, 3, 4, 5, 6, 987654321, time.UTC)
	if err := os.Chtimes(source, stamp, stamp); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(source)
	if err != nil {
		t.Fatal(err)
	}
	oldRename := moveFileRename
	t.Cleanup(func() { moveFileRename = oldRename })
	moveFileRename = func(string, string) error { return syscall.EXDEV }
	if moveErr := moveFile(source, destination); moveErr != nil {
		t.Fatal(moveErr)
	}
	got, err := os.Stat(destination)
	if err != nil {
		t.Fatal(err)
	}
	wantStat, gotStat := info.Sys().(*syscall.Stat_t), got.Sys().(*syscall.Stat_t)
	if got.Mode() != info.Mode() || gotStat.Uid != wantStat.Uid || gotStat.Gid != wantStat.Gid || !got.ModTime().Equal(info.ModTime()) {
		t.Fatalf("cross-device metadata=%+v, want=%+v", got, info)
	}
	data, err := os.ReadFile(destination)
	if err != nil || string(data) != "message body" {
		t.Fatalf("copy=%q, error=%v", data, err)
	}
	if _, statErr := os.Stat(source); !os.IsNotExist(statErr) {
		t.Fatalf("source was not removed: %v", statErr)
	}
}
