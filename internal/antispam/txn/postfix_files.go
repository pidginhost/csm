package txn

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"strings"

	"github.com/pidginhost/csm/internal/antispam"
	"github.com/pidginhost/csm/internal/safepath"
)

func replacementFor(stack antispam.MailStack) func(string, fileState, fileState) error {
	if stack == antispam.StackPostfix {
		return replacePostfixFile
	}
	return replaceFile
}

// Postfix restores operator content as root. Pin every parent so a rename
// or symlink swap cannot redirect the restore or its rollback.
func replacePostfixFile(p string, want, next fileState) error {
	target, err := safepath.OpenTarget("/", strings.TrimPrefix(p, "/"), false)
	if err != nil {
		return err
	}
	defer target.Close()
	if err := target.Check(); err != nil {
		return err
	}
	if err := replacePinned(target, want, next); err != nil {
		return err
	}
	if err := target.Check(); err != nil {
		return fmt.Errorf("%w: %w", errDurability, err)
	}
	return nil
}

func readPinned(dir *safepath.Dir, name string) (fileState, error) {
	f, err := dir.OpenFile(name, os.O_RDONLY, 0)
	if errors.Is(err, fs.ErrNotExist) {
		return fileState{}, nil
	}
	if err != nil {
		return fileState{}, err
	}
	defer func() { _ = f.Close() }()
	return readOpenFile(f)
}

func replacePinned(target *safepath.Target, want, next fileState) error {
	dir, name := target.Parent, target.Name
	cur, err := readPinned(dir, name)
	if err != nil {
		return err
	}
	if !sameContent(cur, want) {
		return errConflict
	}
	if !next.exists {
		if err = dir.Remove(name); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		return syncPinned(dir)
	}
	if len(next.content) > maxFileBytes {
		return errors.New("replacement is too large")
	}
	staging, stageName, err := dir.CreatePrivateTemp()
	if err != nil {
		return err
	}
	defer func() {
		_ = staging.Close()
		_ = dir.RemoveDir(stageName)
	}()
	tmp, err := staging.CreateTemp()
	if err != nil {
		return err
	}
	defer func() {
		_ = tmp.Close()
		_ = staging.Remove(tmp.Name())
	}()
	if _, err = io.WriteString(tmp, next.content); err != nil {
		return err
	}
	cur, err = readPinned(dir, name)
	if err != nil {
		return err
	}
	if !sameContent(cur, want) {
		return errConflict
	}
	meta := fileState{uid: -1, gid: -1, perm: 0o644}
	if cur.exists {
		meta = cur
	}
	if next.metadata {
		meta = next
	}
	if err = tmp.Chown(meta.uid, meta.gid); err != nil {
		return err
	}
	if err = tmp.Chmod(meta.perm); err != nil {
		return err
	}
	if err = tmp.Sync(); err != nil {
		return err
	}
	if cur.exists {
		err = staging.ReplaceTo(tmp.Name(), dir, name)
	} else {
		err = staging.RenameTo(tmp.Name(), dir, name)
	}
	if err != nil {
		return err
	}
	return syncPinned(dir)
}

func syncPinned(dir *safepath.Dir) error {
	if err := dir.Sync(); err != nil {
		return fmt.Errorf("%w: %w", errDurability, err)
	}
	return nil
}
