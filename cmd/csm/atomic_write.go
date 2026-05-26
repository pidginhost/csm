package main

import (
	"fmt"
	"os"
	"path/filepath"
)

// writeFileAtomic writes data to path via a same-directory tempfile,
// fsyncs it, then renames into place. Replaces the common os.WriteFile
// pattern wherever a concurrent reader (sshd reading /etc/pam.d/sshd,
// systemd parsing a unit file, libpam parsing a service file) must
// never observe partial contents.
//
// On any error after the tempfile was created, the tempfile is
// removed so the target directory does not accumulate junk. The mode
// is applied via Chmod before rename so the visible inode lands with
// the right permissions in one step instead of two.
func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	base := filepath.Base(path)
	tmp, err := os.CreateTemp(dir, "."+base+".csm-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp for %s: %w", path, err)
	}
	tmpPath := tmp.Name()
	cleanup := func() {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
	}
	if _, err := tmp.Write(data); err != nil {
		cleanup()
		return fmt.Errorf("write temp for %s: %w", path, err)
	}
	if err := tmp.Sync(); err != nil {
		cleanup()
		return fmt.Errorf("fsync temp for %s: %w", path, err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("close temp for %s: %w", path, err)
	}
	if err := os.Chmod(tmpPath, mode); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("chmod temp for %s: %w", path, err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("rename temp into %s: %w", path, err)
	}
	return nil
}
