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
	temp, err := target.Parent.CreateTemp()
	if err != nil {
		return err
	}
	name := filepath.Base(temp.Name())
	keep := false
	defer func() {
		_ = temp.Close()
		if !keep {
			_ = target.Parent.Remove(name)
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
	if opErr := target.Parent.ExchangeTo(name, target.Parent, target.Name); opErr != nil {
		return fmt.Errorf("%w: %v", ErrVirtualPatchRestoreConflict, opErr)
	}
	// The old inode is checked after isolation. Checking before exchange
	// would permit an intervening replacement to be silently discarded.
	rollback := func(cause error) error {
		if opErr := target.Parent.ExchangeTo(name, target.Parent, target.Name); opErr != nil {
			keep = true
			return fmt.Errorf("%w: %v; rollback failed: %v", ErrVirtualPatchRestoreConflict, cause, opErr)
		}
		return fmt.Errorf("%w: %v", ErrVirtualPatchRestoreConflict, cause)
	}
	oldState, err := readRestoreHtaccess(target.Parent, name)
	if err != nil {
		return rollback(err)
	}
	if !os.SameFile(state.info, oldState.info) || !bytes.Equal(state.content, oldState.content) ||
		state.uid != oldState.uid || state.gid != oldState.gid || state.mode != oldState.mode {
		return rollback(fmt.Errorf("live file changed during restore"))
	}
	current, err := readRestoreHtaccess(target.Parent, target.Name)
	if err != nil {
		return rollback(err)
	}
	if !os.SameFile(prepared, current.info) || !bytes.Equal(content, current.content) ||
		current.uid != meta.Owner || current.gid != meta.Group || current.mode != mode.Perm() {
		return rollback(fmt.Errorf("prepared restore changed"))
	}
	if opErr := target.Check(); opErr != nil {
		return rollback(opErr)
	}
	if meta.RestoreAction == QuarantineRestoreRemoveIfUnchanged {
		if opErr := target.Parent.Remove(target.Name); opErr != nil {
			return rollback(opErr)
		}
	}
	if opErr := target.Parent.Remove(name); opErr != nil {
		keep = true
		return fmt.Errorf("restore applied but replaced file could not be removed: %w", opErr)
	}
	keep = true
	return nil
}

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
