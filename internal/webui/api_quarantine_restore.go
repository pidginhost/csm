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
	"github.com/pidginhost/csm/internal/quarantinefs"
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

	roots, rootErr := quarantineRootsForConfig(s.cfg)
	restorePath, err := validateQuarantineRestorePath(meta.OriginalPath, roots)
	if err != nil {
		writeJSONError(w, errors.Join(err, rootErr).Error(), http.StatusBadRequest)
		return
	}
	if quarantineRestoreAfterValidateForTest != nil {
		quarantineRestoreAfterValidateForTest(restorePath)
	}
	target, err := openQuarantineRestoreTarget(restorePath, roots, meta.RestoreAction == "")
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
		if err := removeRestoredQuarantineEvidence(entry.ItemPath, entry.MetaPath); err != nil {
			writeJSONError(w, err.Error(), http.StatusInternalServerError)
			return
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
		if err := restoreQuarantineDirectory(entry.ItemPath, target, restoredMode, meta); err != nil {
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
		defer src.Close()
		// Allocate cleanup space before creating the destination. A copy may
		// fail because the filesystem is full, when mkdir can fail as well.
		stage, stageName, stageErr := target.Parent.CreatePrivateTemp()
		if stageErr != nil {
			writeJSONError(w, fmt.Sprintf("Cannot stage restored file: %v", stageErr), http.StatusInternalServerError)
			return
		}
		defer func() {
			_ = stage.Close()
			_ = target.Parent.RemoveDir(stageName)
		}()
		const stagedName = "restore"
		dst, createErr := stage.OpenFile(stagedName, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if createErr != nil {
			writeJSONError(w, fmt.Sprintf("Cannot create restored file: %v", createErr), http.StatusInternalServerError)
			return
		}
		// Even a failed first stat can be cleaned safely inside this private
		// directory; no tenant can substitute a different file under its name.
		defer func() { _ = stage.Remove(stagedName) }()
		defer dst.Close()
		createdInfo, statErr := statQuarantineCreatedFile(dst)
		if statErr != nil {
			writeJSONError(w, fmt.Sprintf("Cannot stat restored file: %v", statErr), http.StatusInternalServerError)
			return
		}
		// Keep the inode pinned after dst.Close, preventing inode reuse from
		// making a foreign file pass cleanup's identity check.
		guard, guardErr := stage.OpenFile(stagedName, os.O_RDONLY, 0)
		if guardErr != nil {
			writeJSONError(w, "Cannot pin restored file; quarantine retained", http.StatusInternalServerError)
			return
		}
		defer guard.Close()
		if err := target.Check(); err != nil {
			writeJSONError(w, "Cannot restore - destination changed during restore", http.StatusConflict)
			return
		}
		if err := stage.RenameTo(stagedName, target.Parent, target.Name); err != nil {
			writeJSONError(w, fmt.Sprintf("Cannot restore - file already exists at original path: %v", err), http.StatusConflict)
			return
		}
		keepDestination := false
		defer func() {
			if !keepDestination {
				if err := discardQuarantineRestore(target, createdInfo, stage, stageName); err != nil {
					log.Printf("webui: restore cleanup failed: %v", err)
				}
			}
		}()
		if quarantineRestoreAfterCreateForTest != nil {
			quarantineRestoreAfterCreateForTest(restorePath)
		}
		if _, err := ensureOpenFileStillAtTarget(dst, target); err != nil {
			_ = src.Close()
			writeJSONError(w, "Cannot restore - destination changed during restore", http.StatusConflict)
			return
		}
		_, copyErr := io.Copy(dst, src)
		if closeErr := src.Close(); copyErr == nil && closeErr != nil {
			copyErr = closeErr
		}
		if copyErr != nil {
			writeJSONError(w, fmt.Sprintf("Cannot write restored file: %v", copyErr), http.StatusInternalServerError)
			return
		}
		if quarantineRestoreBeforeFinalizeForTest != nil {
			quarantineRestoreBeforeFinalizeForTest(restorePath)
		}
		if _, err := ensureOpenFileStillAtTarget(dst, target); err != nil {
			writeJSONError(w, "Cannot restore - destination changed during restore", http.StatusConflict)
			return
		}
		if err := dst.Chown(meta.Owner, meta.Group); err != nil {
			writeJSONError(w, fmt.Sprintf("Cannot restore file ownership; quarantine retained: %v", err), http.StatusInternalServerError)
			return
		}
		if err := dst.Chmod(restoredMode); err != nil {
			writeJSONError(w, fmt.Sprintf("Cannot restore file mode: %v", err), http.StatusInternalServerError)
			return
		}
		if !meta.OriginalModTime.IsZero() {
			if err := restoreQuarantineModTime(dst, meta.OriginalModTime); err != nil {
				writeJSONError(w, fmt.Sprintf("Cannot restore modification time; quarantine retained: %v", err), http.StatusInternalServerError)
				return
			}
		}
		restoredInfo, err := ensureOpenFileStillAtTarget(dst, target)
		if err != nil {
			writeJSONError(w, "Cannot restore - destination changed during restore", http.StatusConflict)
			return
		}
		if err := syncQuarantineRestoredFile(dst); err != nil {
			writeJSONError(w, fmt.Sprintf("Restored file could not be synced; quarantine retained: %v", err), http.StatusInternalServerError)
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
		if err := syncQuarantineRestoredParent(target.Parent); err != nil {
			writeJSONError(w, fmt.Sprintf("Restored directory could not be synced; quarantine retained: %v", err), http.StatusInternalServerError)
			return
		}
		if err := ensureTargetStillNamesInfo(target, restoredInfo); err != nil {
			writeJSONError(w, "Cannot restore - destination changed during restore", http.StatusConflict)
			return
		}
		keepDestination = true
	}

	if err := removeRestoredQuarantineEvidence(entry.ItemPath, entry.MetaPath); err != nil {
		writeJSONError(w, err.Error(), http.StatusInternalServerError)
		return
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

var quarantineRestoreBeforeDiscardForTest func()

var syncQuarantineRestoredFile = (*os.File).Sync
var statQuarantineCreatedFile = (*os.File).Stat
var syncQuarantineRestoredParent = (*safepath.Dir).Sync
var removeRestoredQuarantineEvidence = quarantinefs.RemoveEvidence
var restoreQuarantineModTime = safepath.SetModTime

// Isolate the name before testing its inode: checking and then unlinking in
// a tenant-writable parent would allow a replacement between those operations.
// Cleanup uses the pinned parent even if its original pathname was renamed.
func discardQuarantineRestore(target *safepath.Target, want os.FileInfo, stage *safepath.Dir, stageName string) error {
	if quarantineRestoreBeforeDiscardForTest != nil {
		quarantineRestoreBeforeDiscardForTest()
	}
	const name = "discard"
	if err := target.Parent.RenameTo(target.Name, stage, name); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	got, statErr := stage.Stat(name)
	if statErr != nil || !os.SameFile(want, got) {
		if err := stage.RenameTo(name, target.Parent, target.Name); err != nil {
			return fmt.Errorf("destination changed; displaced entry retained in %s: %w", stageName, err)
		}
		return nil
	}
	if err := stage.Remove(name); err != nil {
		return err
	}
	return target.Parent.Sync()
}

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

func openQuarantineRestoreTarget(path string, roots []string, createParents bool) (*safepath.Target, error) {
	var root string
	for _, base := range roots {
		if isPathWithin(path, base) && path != base && len(base) > len(root) {
			root = base
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

func restoreQuarantineDirectory(path string, target *safepath.Target, mode os.FileMode, meta checks.QuarantineMeta) error {
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
	if err := quarantinefs.SyncTree(path, info); err != nil {
		return err
	}
	if err := dir.Chown(meta.Owner, meta.Group); err != nil {
		return err
	}
	if err := dir.Chmod(mode); err != nil {
		return err
	}
	if !meta.OriginalModTime.IsZero() {
		if err := restoreQuarantineModTime(dir, meta.OriginalModTime); err != nil {
			return err
		}
	}
	if err := syncQuarantineRestoredFile(dir); err != nil {
		return err
	}
	if err := dir.Close(); err != nil {
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
	if err := syncQuarantineRestoredParent(target.Parent); err != nil {
		return fmt.Errorf("directory moved to restore destination but sync failed; quarantine metadata retained: %w", err)
	}
	if err := source.Sync(); err != nil {
		return fmt.Errorf("directory restored but quarantine removal is not durable; metadata retained: %w", err)
	}
	return ensureTargetStillNamesInfo(target, info)
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
