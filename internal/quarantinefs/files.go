// Package quarantinefs makes recovery copies durable before callers change
// live files. Its paths must be under an operator-owned quarantine directory.
package quarantinefs

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

var (
	copyContent = io.Copy
	syncFile    = (*os.File).Sync
	closeFile   = (*os.File).Close
)

// EnsureDir persists newly created directory entries, including missing parents.
func EnsureDir(path string, mode os.FileMode) error {
	info, err := os.Stat(path)
	if err == nil {
		if !info.IsDir() {
			return fmt.Errorf("quarantine path is not a directory: %s", path)
		}
		// Another quarantine transaction may have just created this entry.
		return SyncDir(filepath.Dir(path))
	}
	if !os.IsNotExist(err) {
		return err
	}
	parent := filepath.Dir(path)
	if err := EnsureDir(parent, mode); err != nil {
		return err
	}
	if err := os.Mkdir(path, mode); err != nil && !os.IsExist(err) {
		return err
	}
	return SyncDir(parent)
}

// WriteExclusive never overwrites older evidence. Success includes the file's
// contents, its close result, and the containing directory entry reaching disk.
// The caller must first persist the containing directory with EnsureDir.
func WriteExclusive(path string, content io.Reader, mode os.FileMode) (err error) {
	// #nosec G304 -- caller supplies a path under operator-owned quarantine; exclusive creation refuses existing files and symlinks.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	closed := false
	defer func() {
		if !closed {
			err = errors.Join(err, closeFile(f))
		}
		if err != nil {
			if removeErr := os.Remove(path); removeErr != nil && !os.IsNotExist(removeErr) {
				err = errors.Join(err, fmt.Errorf("partial copy retained at %s: %w", path, removeErr))
			}
		}
	}()
	if _, err := copyContent(f, content); err != nil {
		return fmt.Errorf("writing %s: %w", path, err)
	}
	if err := syncFile(f); err != nil {
		return fmt.Errorf("syncing %s: %w", path, err)
	}
	closed = true
	if err := closeFile(f); err != nil {
		return fmt.Errorf("closing %s: %w", path, err)
	}
	return SyncDir(filepath.Dir(path))
}

// Store writes a private content copy and its sidecar before the caller may
// remove or replace the original. On failure the caller must retain the original.
func Store(path string, content io.Reader, metadata []byte, mode os.FileMode) error {
	if err := EnsureDir(filepath.Dir(path), 0700); err != nil {
		return err
	}
	if err := WriteExclusive(path, content, mode); err != nil {
		return err
	}
	if err := WriteExclusive(path+".meta", bytes.NewReader(metadata), 0600); err != nil {
		if removeErr := os.Remove(path); removeErr != nil && !os.IsNotExist(removeErr) {
			return errors.Join(err, fmt.Errorf("copy retained at %s: %w", path, removeErr))
		}
		return fmt.Errorf("writing quarantine metadata: %w", err)
	}
	return nil
}

func SyncDir(path string) error {
	// #nosec G304 -- caller supplies the containing directory of a quarantine or restored file, opened read-only to persist its entries.
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	return errors.Join(syncFile(dir), closeFile(dir))
}

func SyncFilePath(path string) error {
	// #nosec G304 -- caller supplies a quarantine or remediation path; no-follow and regular-file checks reject substituted links and special files.
	f, err := os.OpenFile(path, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	info, err := f.Stat()
	if err != nil {
		return errors.Join(err, closeFile(f))
	}
	if !info.Mode().IsRegular() {
		return errors.Join(fmt.Errorf("cannot sync non-regular file %s", path), closeFile(f))
	}
	return errors.Join(syncFile(f), closeFile(f))
}

// RemoveEvidence runs only after a restored copy and its directory are durable.
// A failed content removal leaves its metadata intact for another recovery attempt.
func RemoveEvidence(path, metaPath string) error {
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("restored, but quarantine content remains at %s: %w", path, err)
	}
	if err := SyncDir(filepath.Dir(path)); err != nil {
		return fmt.Errorf("restored, but quarantine removal is not durable; metadata retained at %s: %w", metaPath, err)
	}
	if err := os.Remove(metaPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("restored, but quarantine metadata remains at %s: %w", metaPath, err)
	}
	return SyncDir(filepath.Dir(metaPath))
}
