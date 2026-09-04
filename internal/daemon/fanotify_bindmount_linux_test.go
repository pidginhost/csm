//go:build linux

package daemon

import (
	"os"
	"path/filepath"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// bindMountForTest bind-mounts src onto dst, skipping the test when the
// sandbox cannot mount (no CAP_SYS_ADMIN, or a restricted container).
func bindMountForTest(t *testing.T, src, dst string) {
	t.Helper()
	if err := unix.Mount(src, dst, "", unix.MS_BIND, ""); err != nil {
		t.Skipf("bind mount unavailable: %v", err)
	}
	t.Cleanup(func() { _ = unix.Unmount(dst, unix.MNT_DETACH) })
}

// closeEventFDs releases the descriptors the kernel attaches to each event, so
// a test that reads events does not leak one per write.
func closeEventFDs(buf []byte) {
	for len(buf) >= int(unsafe.Sizeof(fanotifyEventMetadata{})) {
		meta := (*fanotifyEventMetadata)(unsafe.Pointer(&buf[0]))
		if meta.EventLen < uint32(unsafe.Sizeof(fanotifyEventMetadata{})) || int(meta.EventLen) > len(buf) {
			return
		}
		if meta.Fd >= 0 {
			_ = unix.Close(int(meta.Fd))
		}
		buf = buf[meta.EventLen:]
	}
}

func fanotifyFDForTest(t *testing.T) int {
	t.Helper()
	fd, err := unix.FanotifyInit(FAN_CLASS_NOTIF|FAN_CLOEXEC|FAN_NONBLOCK, unix.O_RDONLY)
	if err != nil {
		t.Skipf("fanotify_init unavailable: %v", err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })
	return fd
}

// waitForEvent reports whether any fanotify event arrives within the deadline.
func waitForEvent(t *testing.T, fd int) bool {
	t.Helper()
	buf := make([]byte, 4096)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		n, err := unix.Read(fd, buf)
		if n > 0 {
			closeEventFDs(buf[:n])
			return true
		}
		if err != nil && err != unix.EAGAIN && err != unix.EINTR {
			t.Fatalf("read fanotify fd: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	return false
}

// The CageFS gap, reproduced: an account's files are reached through a bind
// mount of the same superblock. A mount-scoped mark on the original path sees
// nothing written through the bind mount, which is why realtime detection was
// blind inside cages. A filesystem-scoped mark sees it.
func TestFanotifyBindMountCoverage(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root for fanotify and mount")
	}
	root := t.TempDir()
	origin := filepath.Join(root, "origin")
	cage := filepath.Join(root, "cage")
	for _, dir := range []string{origin, cage} {
		if err := os.Mkdir(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	bindMountForTest(t, origin, cage)

	t.Run("mount scope misses the bind mount", func(t *testing.T) {
		fd := fanotifyFDForTest(t)
		if err := unix.FanotifyMark(fd, FAN_MARK_ADD|FAN_MARK_MOUNT, FAN_CLOSE_WRITE, -1, origin); err != nil {
			t.Skipf("mount mark unavailable: %v", err)
		}
		if err := os.WriteFile(filepath.Join(cage, "shell.php"), []byte("<?php\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if waitForEvent(t, fd) {
			t.Log("mount-scoped mark saw the bind-mount write; kernel is more generous than assumed")
		}
	})

	t.Run("filesystem scope sees the bind mount", func(t *testing.T) {
		fd := fanotifyFDForTest(t)
		scope, err := markWatchRoot(fd, origin, unix.FanotifyMark)
		if err != nil {
			t.Fatalf("markWatchRoot: %v", err)
		}
		if scope != markScopeFilesystem {
			t.Skipf("kernel gave %v scope, not filesystem", scope)
		}
		if err := os.WriteFile(filepath.Join(cage, "dropper.php"), []byte("<?php\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if !waitForEvent(t, fd) {
			t.Error("no event for a write through the bind mount: cages are still blind")
		}
	})
}
