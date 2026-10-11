// Package eximlock serializes CSM's edits and rebuilds of shared Exim
// configuration. Every CSM worker that writes Exim files or runs buildeximconf
// takes this lock first.
package eximlock

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// Dir holds the lock file. Forward guard created this directory first; every
// worker must use the same inode, so the path stays where it is.
const Dir = "/var/lib/csm/forward_guard"

// ErrBusy means another CSM transaction holds the lock. The caller retries
// later; it is not a failed transaction.
var ErrBusy = errors.New("exim mutation lock is held by another CSM transaction")

// With runs mutate while holding dir/mutation.lock, without waiting for it.
// The lock does not exclude cPanel, which edits the same files on its own.
func With(dir string, mutate func() error) error {
	// #nosec G301 -- Exim reads forward guard's bad-IP lookup in this directory as the mail transport user.
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	// #nosec G304 -- fixed CSM state directory; callers cannot supply a path through a worker request.
	file, err := os.OpenFile(filepath.Join(dir, "mutation.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	// Keep the inode after close: unlinking a lock allows two callers to lock
	// different inodes. Close releases the lock even after a failed transaction.
	defer func() { _ = file.Close() }()
	// #nosec G115 -- POSIX file descriptors fit in int.
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return fmt.Errorf("%w: %v", ErrBusy, err)
		}
		return fmt.Errorf("exim mutation lock: %w", err)
	}
	return mutate()
}
