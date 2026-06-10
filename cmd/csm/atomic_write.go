package main

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// writeFileAtomic writes data to path via a same-directory tempfile,
// fsyncs it, then renames into place. Replaces the common os.WriteFile
// pattern wherever a concurrent reader (sshd reading /etc/pam.d/sshd,
// systemd parsing a unit file, libpam parsing a service file) must
// never observe partial contents.
//
// On any error after the tempfile was created, the tempfile is
// removed so the target directory does not accumulate junk. Existing
// files keep their mode and owner; mode applies when path does not
// already exist.
func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	targetPath, targetInfo, err := atomicWriteTarget(path)
	if err != nil {
		return err
	}
	writeMode := mode
	if targetInfo != nil {
		writeMode = targetInfo.Mode().Perm()
	}

	dir := filepath.Dir(targetPath)
	base := filepath.Base(targetPath)
	tmp, err := os.CreateTemp(dir, "."+base+".csm-*.tmp") // #nosec G304 -- temp must be in target dir for atomic rename.
	if err != nil {
		return fmt.Errorf("create temp for %s: %w", path, err)
	}
	tmpPath := tmp.Name()
	cleanup := func() {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
	}
	if targetInfo != nil {
		if err := preserveAtomicWriteOwner(tmp, targetInfo); err != nil {
			cleanup()
			return fmt.Errorf("preserve owner for %s: %w", path, err)
		}
	}
	if _, err := tmp.Write(data); err != nil {
		cleanup()
		return fmt.Errorf("write temp for %s: %w", path, err)
	}
	if err := tmp.Chmod(writeMode); err != nil {
		cleanup()
		return fmt.Errorf("chmod temp for %s: %w", path, err)
	}
	if err := tmp.Sync(); err != nil {
		cleanup()
		return fmt.Errorf("fsync temp for %s: %w", path, err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("close temp for %s: %w", path, err)
	}
	if err := os.Rename(tmpPath, targetPath); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("rename temp into %s: %w", path, err)
	}
	if err := syncParentDir(filepath.Dir(targetPath)); err != nil {
		return err
	}
	return nil
}

func syncParentDir(dir string) error {
	parent, err := os.Open(dir) // #nosec G304 -- dir is derived from caller-owned target path.
	if err != nil {
		return fmt.Errorf("open parent dir %s: %w", dir, err)
	}
	if err := parent.Sync(); err != nil {
		_ = parent.Close()
		return fmt.Errorf("fsync parent dir %s: %w", dir, err)
	}
	if err := parent.Close(); err != nil {
		return fmt.Errorf("close parent dir %s: %w", dir, err)
	}
	return nil
}

func atomicWriteTarget(path string) (string, os.FileInfo, error) {
	info, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return path, nil, nil
		}
		return "", nil, fmt.Errorf("stat %s: %w", path, err)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		return path, info, nil
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", nil, fmt.Errorf("resolve symlink %s: %w", path, err)
	}
	targetInfo, err := os.Stat(resolved)
	if err != nil {
		return "", nil, fmt.Errorf("stat symlink target %s: %w", path, err)
	}
	return resolved, targetInfo, nil
}

func preserveAtomicWriteOwner(tmp *os.File, targetInfo os.FileInfo) error {
	targetStat, ok := targetInfo.Sys().(*syscall.Stat_t)
	if !ok {
		return nil
	}
	tmpInfo, err := tmp.Stat()
	if err != nil {
		return err
	}
	tmpStat, ok := tmpInfo.Sys().(*syscall.Stat_t)
	if ok && tmpStat.Uid == targetStat.Uid && tmpStat.Gid == targetStat.Gid {
		return nil
	}
	return tmp.Chown(int(targetStat.Uid), int(targetStat.Gid))
}
