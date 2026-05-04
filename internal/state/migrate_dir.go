package state

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
)

// MigrateStateDir copies the contents of oldPath into newPath if and only if:
// (1) oldPath exists and is non-empty,
// (2) newPath does not exist or is empty,
// (3) the two paths are not the same.
// Returns (true, nil) when a copy occurred, (false, nil) when no migration
// was needed. Any I/O error is fatal — the caller (daemon startup) should
// abort rather than silently start with mixed state.
func MigrateStateDir(oldPath, newPath string) (bool, error) {
	if oldPath == "" || newPath == "" || oldPath == newPath {
		return false, nil
	}
	oldInfo, err := os.Stat(oldPath)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return false, nil
		}
		return false, fmt.Errorf("stat %s: %w", oldPath, err)
	}
	if !oldInfo.IsDir() {
		return false, nil
	}
	oldEntries, err := os.ReadDir(oldPath)
	if err != nil {
		return false, fmt.Errorf("reading %s: %w", oldPath, err)
	}
	if len(oldEntries) == 0 {
		return false, nil
	}

	if newEntries, err := os.ReadDir(newPath); err == nil && len(newEntries) > 0 {
		return false, nil // new dir non-empty: no migration
	} else if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return false, fmt.Errorf("reading %s: %w", newPath, err)
	}

	if err := os.MkdirAll(newPath, 0o700); err != nil {
		return false, fmt.Errorf("mkdir %s: %w", newPath, err)
	}

	for _, e := range oldEntries {
		src := filepath.Join(oldPath, e.Name())
		dst := filepath.Join(newPath, e.Name())
		if err := copyEntry(src, dst); err != nil {
			return false, fmt.Errorf("copying %s: %w", src, err)
		}
	}
	return true, nil
}

func copyEntry(src, dst string) error {
	info, err := os.Stat(src)
	if err != nil {
		return err
	}
	if info.IsDir() {
		if mkdirErr := os.MkdirAll(dst, info.Mode().Perm()); mkdirErr != nil {
			return mkdirErr
		}
		entries, readDirErr := os.ReadDir(src)
		if readDirErr != nil {
			return readDirErr
		}
		for _, e := range entries {
			if copyErr := copyEntry(filepath.Join(src, e.Name()), filepath.Join(dst, e.Name())); copyErr != nil {
				return copyErr
			}
		}
		return nil
	}
	// #nosec G304 -- src derived from os.ReadDir of a trusted state directory.
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	// #nosec G304 -- dst is new state directory plus an entry name from os.ReadDir.
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, info.Mode().Perm())
	if err != nil {
		return err
	}
	defer out.Close()
	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	return out.Sync()
}
