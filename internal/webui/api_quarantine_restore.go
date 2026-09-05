package webui

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"

	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/safepath"
)

// apiQuarantineRestore restores a quarantined file to its original location.
// POST /api/v1/quarantine-restore  body: {"id": "filename"}
func (s *Server) apiQuarantineRestore(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		ID string `json:"id"`
	}
	if err := decodeJSONBodyLimited(w, r, 16*1024, &req); err != nil || req.ID == "" {
		writeJSONError(w, "ID is required", http.StatusBadRequest)
		return
	}

	entry, err := resolveQuarantineEntry(req.ID)
	if err != nil {
		writeJSONError(w, err.Error(), http.StatusBadRequest)
		return
	}
	if !quarantineEntryDeletable(entry) {
		writeJSONError(w, "Quarantine entry not found", http.StatusNotFound)
		return
	}

	metaData, err := os.ReadFile(entry.MetaPath)
	if err != nil {
		writeJSONError(w, "Quarantine entry not found", http.StatusNotFound)
		return
	}

	var meta checks.QuarantineMeta
	if unmarshalErr := json.Unmarshal(metaData, &meta); unmarshalErr != nil {
		writeJSONError(w, "Invalid metadata", http.StatusInternalServerError)
		return
	}

	restorePath, err := validateQuarantineRestorePath(meta.OriginalPath)
	if err != nil {
		writeJSONError(w, err.Error(), http.StatusBadRequest)
		return
	}
	if quarantineRestoreAfterValidateForTest != nil {
		quarantineRestoreAfterValidateForTest(restorePath)
	}
	target, err := openQuarantineRestoreTarget(restorePath, meta.RestoreAction == "")
	if err != nil {
		writeJSONError(w, fmt.Sprintf("Cannot open restore destination: %v", err), http.StatusConflict)
		return
	}
	defer target.Close()

	// Check if quarantined item is a directory or file
	quarInfo, err := os.Lstat(entry.ItemPath)
	if err != nil {
		writeJSONError(w, fmt.Sprintf("Cannot stat quarantined file: %v", err), http.StatusInternalServerError)
		return
	}
	if quarInfo.Mode()&os.ModeSymlink != 0 {
		writeJSONError(w, "Cannot restore symlink quarantine entry", http.StatusInternalServerError)
		return
	}

	// Parse original mode from metadata (format: "-rw-r--r--" or "drwxr-xr-x")
	restoredMode := os.FileMode(0644)
	if meta.Mode != "" && len(meta.Mode) >= 10 {
		restoredMode = parseModeString(meta.Mode)
	}

	if meta.RestoreAction != "" {
		if filepath.Clean(filepath.Dir(entry.ItemPath)) != filepath.Join(quarantineDir, "pre_clean") {
			writeJSONError(w, "Virtual-patch backups must come from pre_clean", http.StatusBadRequest)
			return
		}
		if quarInfo.IsDir() {
			writeJSONError(w, "Invalid virtual-patch backup", http.StatusInternalServerError)
			return
		}
		if err := checks.RestoreVirtualPatchBackup(entry.ItemPath, target, meta); err != nil {
			if errors.Is(err, checks.ErrVirtualPatchRestoreConflict) {
				writeJSONError(w, err.Error(), http.StatusConflict)
				return
			}
			writeJSONError(w, fmt.Sprintf("Cannot restore virtual-patch backup: %v", err), http.StatusInternalServerError)
			return
		}
		if err := os.Remove(entry.ItemPath); err != nil && !os.IsNotExist(err) {
			log.Printf("webui: failed to remove %s: %v", safeLogString(entry.ItemPath), err)
		}
		if err := os.Remove(entry.MetaPath); err != nil && !os.IsNotExist(err) {
			log.Printf("webui: failed to remove %s: %v", safeLogString(entry.MetaPath), err)
		}
		s.auditLog(r, "restore", restorePath, "virtual-patch restore")
		writeJSON(w, map[string]string{
			"status":  "restored",
			"path":    restorePath,
			"warning": "Virtual-patch reverted. Re-scan recommended.",
		})
		return
	}

	if err := target.Check(); err != nil {
		writeJSONError(w, err.Error(), http.StatusConflict)
		return
	}

	if quarInfo.IsDir() {
		if err := restoreQuarantineDirectory(entry.ItemPath, target, restoredMode, meta.Owner, meta.Group); err != nil {
			writeJSONError(w, fmt.Sprintf("Cannot restore directory: %v", err), http.StatusConflict)
			return
		}
	} else {
		// File restore: use O_EXCL to prevent overwriting an existing file
		src, readErr := os.Open(entry.ItemPath)
		if readErr != nil {
			writeJSONError(w, fmt.Sprintf("Cannot read quarantined file: %v", readErr), http.StatusInternalServerError)
			return
		}
		dst, createErr := target.Parent.OpenFile(target.Name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if createErr != nil {
			_ = src.Close()
			writeJSONError(w, fmt.Sprintf("Cannot restore - file already exists at original path: %v", createErr), http.StatusConflict)
			return
		}
		if quarantineRestoreAfterCreateForTest != nil {
			quarantineRestoreAfterCreateForTest(restorePath)
		}
		if _, err := ensureOpenFileStillAtTarget(dst, target); err != nil {
			_ = src.Close()
			_ = dst.Close()
			writeJSONError(w, "Cannot restore - destination changed during restore", http.StatusConflict)
			return
		}
		_, copyErr := io.Copy(dst, src)
		if closeErr := src.Close(); copyErr == nil && closeErr != nil {
			copyErr = closeErr
		}
		if copyErr != nil {
			_ = dst.Close()
			writeJSONError(w, fmt.Sprintf("Cannot write restored file: %v", copyErr), http.StatusInternalServerError)
			return
		}
		if quarantineRestoreBeforeFinalizeForTest != nil {
			quarantineRestoreBeforeFinalizeForTest(restorePath)
		}
		if _, err := ensureOpenFileStillAtTarget(dst, target); err != nil {
			_ = dst.Close()
			writeJSONError(w, "Cannot restore - destination changed during restore", http.StatusConflict)
			return
		}
		if err := dst.Chmod(restoredMode); err != nil {
			_ = dst.Close()
			writeJSONError(w, fmt.Sprintf("Cannot restore file mode: %v", err), http.StatusInternalServerError)
			return
		}
		if err := dst.Chown(meta.Owner, meta.Group); err != nil {
			log.Printf("webui: chown %s after restore failed: %v", safeLogString(restorePath), err)
		}
		restoredInfo, err := ensureOpenFileStillAtTarget(dst, target)
		if err != nil {
			_ = dst.Close()
			writeJSONError(w, "Cannot restore - destination changed during restore", http.StatusConflict)
			return
		}
		if err := dst.Close(); err != nil {
			writeJSONError(w, fmt.Sprintf("Cannot write restored file: %v", err), http.StatusInternalServerError)
			return
		}
		if err := ensureTargetStillNamesInfo(target, restoredInfo); err != nil {
			writeJSONError(w, "Cannot restore - destination changed during restore", http.StatusConflict)
			return
		}
		if err := os.Remove(entry.ItemPath); err != nil && !os.IsNotExist(err) {
			log.Printf("webui: failed to remove %s: %v", safeLogString(entry.ItemPath), err)
		}
	}

	// Remove metadata sidecar
	if err := os.Remove(entry.MetaPath); err != nil && !os.IsNotExist(err) {
		log.Printf("webui: failed to remove %s: %v", safeLogString(entry.MetaPath), err)
	}

	s.auditLog(r, "restore", restorePath, "quarantine restore")
	writeJSON(w, map[string]string{
		"status":  "restored",
		"path":    restorePath,
		"warning": "File restored to original location. Re-scan recommended.",
	})
}

// quarantineRestoreAfterCreateForTest lets race tests replace the path
// after O_EXCL creation; nil in production.
var quarantineRestoreAfterCreateForTest func(string)

var quarantineRestoreAfterValidateForTest func(string)

var quarantineRestoreBeforeFinalizeForTest func(string)

func ensureOpenFileStillAtTarget(f *os.File, target *safepath.Target) (os.FileInfo, error) {
	fileInfo, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("cannot stat restored file handle: %w", err)
	}
	if err := ensureTargetStillNamesInfo(target, fileInfo); err != nil {
		return nil, err
	}
	return fileInfo, nil
}

func ensureTargetStillNamesInfo(target *safepath.Target, fileInfo os.FileInfo) error {
	if err := target.Check(); err != nil {
		return err
	}
	pathInfo, err := target.Parent.Stat(target.Name)
	if err != nil {
		return fmt.Errorf("cannot stat restored file path: %w", err)
	}
	if !os.SameFile(fileInfo, pathInfo) {
		return fmt.Errorf("restore destination changed during restore")
	}
	return nil
}

func openQuarantineRestoreTarget(path string, createParents bool) (*safepath.Target, error) {
	var root string
	for _, base := range quarantineRestoreRoots {
		for _, candidate := range []string{base, resolvedRestoreRoot(base)} {
			if candidate != "" && isPathWithin(path, candidate) && path != candidate && len(candidate) > len(root) {
				root = candidate
			}
		}
	}
	if root == "" {
		return nil, fmt.Errorf("restore path is outside the allowed restore roots")
	}
	relative, err := filepath.Rel(root, path)
	if err != nil {
		return nil, err
	}
	return safepath.OpenTarget(root, relative, createParents)
}

func resolvedRestoreRoot(path string) string {
	resolved, _ := filepath.EvalSymlinks(path)
	return resolved
}

func restoreQuarantineDirectory(path string, target *safepath.Target, mode os.FileMode, uid, gid int) error {
	// Quarantine is daemon-owned. Both sides of the rename still use pinned
	// parents so destination swaps cannot redirect the transaction.
	source, err := safepath.OpenDir(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer func() { _ = source.Close() }()
	name := filepath.Base(path)
	dir, err := source.OpenFile(name, os.O_RDONLY, 0)
	if err != nil {
		return err
	}
	defer dir.Close()
	info, err := dir.Stat()
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("quarantine entry is no longer a directory")
	}
	if err := dir.Chmod(mode); err != nil {
		return err
	}
	if err := dir.Chown(uid, gid); err != nil {
		return err
	}
	if err := target.Check(); err != nil {
		return err
	}
	if err := source.RenameTo(name, target.Parent, target.Name); err != nil {
		return err
	}
	if quarantineRestoreAfterDirectoryMoveForTest != nil {
		quarantineRestoreAfterDirectoryMoveForTest()
	}
	if err := ensureTargetStillNamesInfo(target, info); err != nil {
		if rollbackErr := rollbackQuarantineDirectory(source, name, target, info); rollbackErr != nil {
			return fmt.Errorf("%w; restoring quarantine entry failed: %v", err, rollbackErr)
		}
		return err
	}
	return nil
}

var quarantineRestoreAfterDirectoryMoveForTest func()

// Rollback must identify the isolated inode, not a name a tenant can replace
// between validation and rename. Foreign entries go back without overwriting.
func rollbackQuarantineDirectory(source *safepath.Dir, name string, target *safepath.Target, want os.FileInfo) error {
	stage, stageName, err := source.CreatePrivateTemp()
	if err != nil {
		return err
	}
	defer func() {
		_ = stage.Close()
		_ = source.RemoveDir(stageName)
	}()
	const displaced = "displaced"
	if err := target.Parent.RenameTo(target.Name, stage, displaced); err != nil {
		return err
	}
	got, statErr := stage.Stat(displaced)
	if statErr != nil || !os.SameFile(want, got) {
		if err := stage.RenameTo(displaced, target.Parent, target.Name); err != nil {
			return fmt.Errorf("destination changed; displaced entry retained in %s: %w", stageName, err)
		}
		return fmt.Errorf("destination changed; quarantine directory was moved by another writer")
	}
	if err := stage.RenameTo(displaced, source, name); err != nil {
		return fmt.Errorf("quarantine directory retained in %s: %w", stageName, err)
	}
	return nil
}
