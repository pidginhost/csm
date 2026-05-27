package state

import (
	"encoding/json"
	"fmt"
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
	dir := filepath.Dir(path)
	tmp := path + ".tmp"
	// #nosec G304 -- caller owns the destination path; tmp is derived
	// from it deterministically and lives in the same operator-owned
	// state directory.
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
	if err != nil {
		return fmt.Errorf("open tmp: %w", err)
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("write tmp: %w", err)
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
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}
