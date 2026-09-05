package adapter

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"github.com/pidginhost/csm/internal/mailfwd/policy"
)

type lockedEximAdapter struct{ *EximAdapter }

func (a lockedEximAdapter) Apply(cfg policy.Config, ips []string) error {
	return withEximMutationLock(filepath.Dir(a.badIPsPath), func() error { return a.EximAdapter.Apply(cfg, ips) })
}

func (a lockedEximAdapter) Remove() error {
	return withEximMutationLock(filepath.Dir(a.badIPsPath), a.EximAdapter.Remove)
}

func withEximMutationLock(dir string, mutate func() error) error {
	// #nosec G301 -- Exim reads the bad-IP lookup in this directory as the mail transport user.
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	// #nosec G304 -- fixed CSM state directory; callers cannot supply a path through the helper protocol.
	file, err := os.OpenFile(filepath.Join(dir, "mutation.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	// Keep the inode after close: unlinking a lock allows two callers to lock
	// different inodes. Close releases the lock even after a failed transaction.
	defer func() { _ = file.Close() }()
	// #nosec G115 -- POSIX file descriptors fit in int.
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return fmt.Errorf("forward-guard transaction lock unavailable: %w", err)
	}
	return mutate()
}
