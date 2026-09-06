//go:build linux

package safepath

import (
	"os"
	"runtime"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// SetModTime changes only the pinned inode, preserving nanosecond precision.
func SetModTime(file *os.File, mtime time.Time) error {
	ts, err := unix.TimeToTimespec(mtime)
	if err != nil {
		return err
	}
	times := [2]unix.Timespec{{Nsec: unix.UTIME_OMIT}, ts}
	// This is the kernel's futimens ABI. A NULL pathname operates on the fd
	// without the newer AT_EMPTY_PATH flag or resolving a tenant-owned name.
	// #nosec G103 -- fixed timespec array passed directly to a synchronous fd-only syscall; no pointer arithmetic or user-controlled address.
	_, _, errno := unix.Syscall6(unix.SYS_UTIMENSAT, file.Fd(), 0, uintptr(unsafe.Pointer(&times[0])), 0, 0, 0)
	runtime.KeepAlive(file)
	if errno != 0 {
		return &os.PathError{Op: "futimens", Path: file.Name(), Err: errno}
	}
	return nil
}
