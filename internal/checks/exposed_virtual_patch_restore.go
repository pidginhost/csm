package checks

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"github.com/pidginhost/csm/internal/safepath"
)

// RestoreVirtualPatchBackup reverts only the captured patch, using the pinned
// destination directory so tenant renames cannot redirect reads or changes.
func RestoreVirtualPatchBackup(backupPath string, target *safepath.Target, meta QuarantineMeta) error {
	if target.Name != ".htaccess" {
		return fmt.Errorf("virtual-patch restore applies only to .htaccess")
	}
	if meta.RestoreAction != QuarantineRestoreReplaceIfUnchanged &&
		meta.RestoreAction != QuarantineRestoreRemoveIfUnchanged {
		return fmt.Errorf("unsupported virtual-patch restore action %q", meta.RestoreAction)
	}
	mode, err := parseVirtualPatchMode(meta.Mode)
	if err != nil {
		return err
	}
	state, err := readRestoreHtaccess(target.Parent, target.Name)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrVirtualPatchRestoreConflict, err)
	}
	if virtualPatchSHA256(state.content) != meta.ExpectedCurrentSHA256 ||
		state.uid != meta.Owner || state.gid != meta.Group || state.mode.Perm() != mode.Perm() {
		return fmt.Errorf("%w: live file was modified after enforcement", ErrVirtualPatchRestoreConflict)
	}
	var content []byte
	if meta.RestoreAction == QuarantineRestoreReplaceIfUnchanged {
		// Quarantine is daemon-owned; the final backup name is still opened
		// without following a symlink and validated before reading.
		backup, openErr := os.OpenFile(backupPath, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0) // #nosec G304 -- caller supplies a daemon-owned quarantine entry; no-follow and regular-file checks protect the read
		if openErr != nil {
			return fmt.Errorf("opening virtual-patch backup: %w", openErr)
		}
		content, err = readRestoreContent(backup)
		closeErr := backup.Close()
		if err != nil {
			return err
		}
		if closeErr != nil {
			return closeErr
		}
	}
	if opErr := target.Check(); opErr != nil {
		return fmt.Errorf("%w: %v", ErrVirtualPatchRestoreConflict, opErr)
	}
	stage, stageName, err := target.Parent.CreatePrivateTemp()
	if err != nil {
		return err
	}
	defer func() { _ = stage.Close() }()
	keep := false
	defer func() {
		if !keep {
			_ = target.Parent.RemoveDir(stageName)
		}
	}()
	temp, err := stage.CreateTemp()
	if err != nil {
		return err
	}
	name := filepath.Base(temp.Name())
	defer func() {
		_ = temp.Close()
		if !keep {
			_ = stage.Remove(name)
		}
	}()
	if _, opErr := temp.Write(content); opErr != nil {
		return opErr
	}
	if opErr := temp.Chmod(mode); opErr != nil {
		return opErr
	}
	if opErr := temp.Chown(meta.Owner, meta.Group); opErr != nil {
		return opErr
	}
	if !meta.OriginalModTime.IsZero() {
		if opErr := safepath.SetModTime(temp, meta.OriginalModTime); opErr != nil {
			return opErr
		}
	}
	if opErr := temp.Sync(); opErr != nil {
		return opErr
	}
	prepared, err := temp.Stat()
	if err != nil {
		return err
	}
	if opErr := temp.Close(); opErr != nil {
		return opErr
	}
	if opErr := target.Check(); opErr != nil {
		return fmt.Errorf("%w: %v", ErrVirtualPatchRestoreConflict, opErr)
	}
	remove := meta.RestoreAction == QuarantineRestoreRemoveIfUnchanged
	if remove {
		if opErr := stage.Remove(name); opErr != nil {
			return opErr
		}
		// Isolate the old file without leaving a placeholder whose later
		// unlink could delete a concurrent replacement at the live name.
		err = target.Parent.RenameTo(target.Name, stage, name)
	} else {
		err = stage.ExchangeTo(name, target.Parent, target.Name)
	}
	if err != nil {
		return fmt.Errorf("%w: %v", ErrVirtualPatchRestoreConflict, err)
	}
	if virtualPatchRestoreAfterMoveForTest != nil {
		virtualPatchRestoreAfterMoveForTest()
	}
	conflict := func(cause error) error {
		keep = true
		return fmt.Errorf("%w: %v; recovery files retained in %s", ErrVirtualPatchRestoreConflict, cause, stageName)
	}
	rollback := func(cause error) error {
		keep = true
		if remove {
			if opErr := stage.RenameTo(name, target.Parent, target.Name); opErr != nil {
				return conflict(fmt.Errorf("%v; rollback failed: %w", cause, opErr))
			}
			keep = false
			return fmt.Errorf("%w: %v", ErrVirtualPatchRestoreConflict, cause)
		}
		// Capture the live name before deciding what to put back. A second
		// exchange after a check could overwrite another intervening edit.
		captured, opErr := stage.CreateTemp()
		if opErr != nil {
			return conflict(opErr)
		}
		captureName := filepath.Base(captured.Name())
		if opErr := captured.Close(); opErr != nil {
			return conflict(opErr)
		}
		if opErr := stage.Remove(captureName); opErr != nil {
			return conflict(opErr)
		}
		captureErr := target.Parent.RenameTo(target.Name, stage, captureName)
		if captureErr != nil && !os.IsNotExist(captureErr) {
			return conflict(fmt.Errorf("%v; rollback failed: %w", cause, captureErr))
		}
		restoreName := name
		if captureErr == nil {
			current, readErr := readRestoreHtaccess(stage, captureName)
			if readErr != nil || !os.SameFile(prepared, current.info) ||
				!bytes.Equal(content, current.content) || current.uid != meta.Owner ||
				current.gid != meta.Group || current.mode != mode.Perm() {
				restoreName = captureName
			}
		}
		if opErr := stage.RenameTo(restoreName, target.Parent, target.Name); opErr != nil {
			return conflict(fmt.Errorf("%v; rollback failed: %w", cause, opErr))
		}
		if captureErr != nil {
			keep = false
			return fmt.Errorf("%w: %v", ErrVirtualPatchRestoreConflict, cause)
		}
		// Keep every captured inode on conflict, including one that looked
		// unchanged: a writer may still hold an open descriptor to it.
		return conflict(cause)
	}
	oldState, err := readRestoreHtaccess(stage, name)
	if err != nil {
		return rollback(err)
	}
	if !os.SameFile(state.info, oldState.info) || !bytes.Equal(state.content, oldState.content) ||
		state.uid != oldState.uid || state.gid != oldState.gid || state.mode != oldState.mode {
		return rollback(fmt.Errorf("live file changed during restore"))
	}
	if remove {
		if _, statErr := target.Parent.Stat(target.Name); !os.IsNotExist(statErr) {
			return conflict(fmt.Errorf("live file was recreated during restore"))
		}
	} else {
		current, readErr := readRestoreHtaccess(target.Parent, target.Name)
		if readErr != nil {
			return rollback(readErr)
		}
		if !os.SameFile(prepared, current.info) || !bytes.Equal(content, current.content) ||
			current.uid != meta.Owner || current.gid != meta.Group || current.mode != mode.Perm() {
			return conflict(fmt.Errorf("prepared restore changed"))
		}
	}
	if opErr := target.Check(); opErr != nil {
		return rollback(opErr)
	}
	if opErr := target.Parent.Sync(); opErr != nil {
		keep = true
		return fmt.Errorf("restore applied but destination sync failed; recovery files retained in %s: %w", stageName, opErr)
	}
	if opErr := stage.Remove(name); opErr != nil {
		keep = true
		return fmt.Errorf("restore applied but replaced file could not be removed from %s: %w", stageName, opErr)
	}
	return nil
}

var virtualPatchRestoreAfterMoveForTest func()

func readRestoreContent(file *os.File) ([]byte, error) {
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > maxVirtualPatchHtaccessSize {
		return nil, fmt.Errorf("restore input must be a bounded regular file")
	}
	content, err := io.ReadAll(io.LimitReader(file, maxVirtualPatchHtaccessSize+1))
	if err != nil {
		return nil, err
	}
	if len(content) > maxVirtualPatchHtaccessSize {
		return nil, fmt.Errorf("restore input exceeds size limit")
	}
	return content, nil
}

func readRestoreHtaccess(dir *safepath.Dir, name string) (htaccessState, error) {
	file, err := dir.OpenFile(name, os.O_RDONLY, 0)
	if err != nil {
		return htaccessState{}, err
	}
	defer file.Close()
	content, err := readRestoreContent(file)
	if err != nil {
		return htaccessState{}, err
	}
	info, err := file.Stat()
	if err != nil {
		return htaccessState{}, err
	}
	uid, gid, err := ownerFromInfo(info)
	if err != nil {
		return htaccessState{}, err
	}
	return htaccessState{content: content, info: info, existed: true, uid: uid, gid: gid, mode: info.Mode().Perm()}, nil
}
