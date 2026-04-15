package state

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// LockFile provides file-based locking to prevent concurrent CSM runs.
type LockFile struct {
	path string
	file *os.File
}

// AcquireLock creates an exclusive lock. Returns error if already locked.
func AcquireLock(stateDir string) (*LockFile, error) {
	lockPath := filepath.Join(stateDir, "csm.lock")
	// #nosec G304 -- filepath.Join under operator-configured stateDir.
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, fmt.Errorf("opening lock file: %w", err)
	}

	// Try non-blocking exclusive lock
	// #nosec G115 -- os.File.Fd returns uintptr but POSIX file descriptors
	// are small non-negative ints (rlimit ~1024); int conversion is lossless.
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("another CSM instance is already running")
	}

	// Write PID for debugging
	_ = f.Truncate(0)
	fmt.Fprintf(f, "%d\n", os.Getpid())

	return &LockFile{path: lockPath, file: f}, nil
}

// Release releases the lock.
func (l *LockFile) Release() {
	if l.file != nil {
		// #nosec G115 -- see AcquireLock: POSIX fd fits in int.
		_ = syscall.Flock(int(l.file.Fd()), syscall.LOCK_UN)
		_ = l.file.Close()
		os.Remove(l.path)
	}
}
