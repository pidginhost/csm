// Package atomicio implements atomic file writes used by state-bearing
// callers (firewall engine, autoblock tracker, etc.). The package is a
// dependency leaf: it imports only the standard library so any caller
// can use AtomicWriteJSON without risking an import cycle through the
// existing state / store packages.
package atomicio

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// AtomicWriteJSON marshals v to JSON and writes it to path atomically:
// MarshalIndent, write tmp, fsync tmp, rename. Returns the first error
// encountered. On rename failure the tmp file is removed best-effort.
//
// Reserved for state files that callers re-read on the next startup or
// the next tick - a torn write would leave the daemon with stale or
// corrupt state. Hot-path callers that only need a best-effort cache
// dump should not use this helper.
func AtomicWriteJSON(path string, perm os.FileMode, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	return AtomicWrite(path, perm, data)
}

// AtomicWrite writes already-serialized bytes to path atomically with the
// same write-tmp, fsync, rename, dir-fsync sequence as AtomicWriteJSON.
func AtomicWrite(path string, perm os.FileMode, data []byte) error {
	dir := filepath.Dir(path)
	legacyTmp := path + ".tmp"
	if removeErr := os.Remove(legacyTmp); removeErr != nil && !os.IsNotExist(removeErr) {
		return fmt.Errorf("remove stale tmp: %w", removeErr)
	}
	// #nosec G304 -- caller owns the destination path; tmp lives in
	// the same operator-owned state directory.
	f, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return fmt.Errorf("open tmp: %w", err)
	}
	tmp := f.Name()
	if err := f.Chmod(perm); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("chmod tmp: %w", err)
	}
	if n, err := f.Write(data); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("write tmp: %w", err)
	} else if n != len(data) {
		_ = f.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("write tmp: %w", io.ErrShortWrite)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("fsync tmp: %w", err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("close tmp: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("rename: %w", err)
	}
	// #nosec G304 -- dir is filepath.Dir of caller-owned path; opened
	// read-only solely to fsync the directory after rename so the
	// new dentry survives a power-loss.
	d, openErr := os.Open(dir)
	if openErr != nil {
		return fmt.Errorf("open dir: %w", openErr)
	}
	if err := d.Sync(); err != nil {
		_ = d.Close()
		return fmt.Errorf("fsync dir: %w", err)
	}
	if err := d.Close(); err != nil {
		return fmt.Errorf("close dir: %w", err)
	}
	return nil
}
