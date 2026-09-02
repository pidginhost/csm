package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// renameExportFile is os.Rename behind a seam so tests can force the
// cross-filesystem path.
var renameExportFile = os.Rename

// moveExportedArchive moves a staged export (and its .sha256 companion)
// from the daemon's state directory to the operator's destination. A
// rename is tried first; across filesystems the archive is copied, fsynced
// and verified against wantSHA before the staged copy is removed, so a
// truncated copy never replaces a good archive silently.
//
// #nosec G304 G703 -- src is the daemon's staged export path and dst is the
// destination the operator named on the command line; both are root-only
// inputs, and the export subcommand already runs as root.
func moveExportedArchive(src, dst, wantSHA string) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o750); err != nil {
		return fmt.Errorf("creating destination directory: %w", err)
	}
	if err := assertExportDirPrivate(filepath.Dir(dst)); err != nil {
		return err
	}
	if err := renameExportFile(src, dst); err == nil {
		_ = renameExportFile(src+".sha256", dst+".sha256")
		// Nothing else references the staged copy after this, so the new
		// directory entries have to survive a crash on their own.
		return syncParentDir(filepath.Dir(dst))
	} else if !isCrossDevice(err) {
		return fmt.Errorf("moving archive into place: %w", err)
	}

	if err := copyFileVerified(src, dst, wantSHA); err != nil {
		return err
	}
	if companion, err := os.ReadFile(src + ".sha256"); err == nil {
		if err := writeExportFileAtomic(dst+".sha256", companion); err != nil {
			return fmt.Errorf("writing companion digest: %w", err)
		}
	}
	_ = os.Remove(src + ".sha256")
	if err := os.Remove(src); err != nil {
		return fmt.Errorf("removing staged archive: %w", err)
	}
	return nil
}

func isCrossDevice(err error) bool {
	return errors.Is(err, syscall.EXDEV)
}

// assertExportDirPrivate refuses a destination another account can write to.
// Verifying the copy proves nothing there: whoever can write to the
// directory can rename the verified file out of the way between the digest
// check and the rename that commits it, and would end up choosing what the
// operator receives as the export.
//
// Every ancestor is checked, not just the destination directory itself.
// Renaming a directory entry is governed by the permissions of the
// directory holding it, so a private directory under a shared parent can be
// swapped whole. Symlinks are resolved first so a link cannot stand in for
// a directory that passed the check.
//
// The sticky bit is the exception that keeps /tmp working -- entries can be
// created there but only their owner may rename or remove them. Components
// owned by root are accepted because root can write anywhere regardless.
func assertExportDirPrivate(dir string) error {
	resolved, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return fmt.Errorf("checking destination directory: %w", err)
	}
	if !filepath.IsAbs(resolved) {
		return fmt.Errorf("export destination %s must be an absolute path", dir)
	}
	self := os.Geteuid()
	current := string(filepath.Separator)
	if err := assertExportPathComponentPrivate(current, self); err != nil {
		return err
	}
	for _, part := range strings.Split(strings.Trim(resolved, string(filepath.Separator)), string(filepath.Separator)) {
		if part == "" {
			continue
		}
		current = filepath.Join(current, part)
		if err := assertExportPathComponentPrivate(current, self); err != nil {
			return err
		}
	}
	return nil
}

// #nosec G703 -- path is one component of the destination the operator named.
func assertExportPathComponentPrivate(path string, self int) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("checking destination directory: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("export destination component %s is not a directory", path)
	}
	if info.Mode().Perm()&0o022 != 0 && info.Mode()&os.ModeSticky == 0 {
		return fmt.Errorf("refusing to export into %s: it is writable by other accounts", path)
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); ok && int(stat.Uid) != self && stat.Uid != 0 {
		return fmt.Errorf("refusing to export into %s: it is owned by uid %d, which can replace the archive after it is verified", path, stat.Uid)
	}
	return nil
}

// copyFileVerified copies src into a private temporary file beside dst,
// syncs it, checks the SHA-256 of the bytes written against wantSHA
// (skipped when wantSHA is empty) and only then renames it over dst.
//
// Opening dst directly would follow a symlink a local account planted at
// that path -- the destination is often /tmp, which is both world-writable
// and on a different filesystem from the daemon's state directory, so it
// always takes this path -- and would inherit whatever mode an existing
// object already had. Renaming replaces the object at dst instead of
// writing through it, and leaves a previous export intact when the copy
// cannot be verified.
//
// #nosec G304 G703 -- same root-only src and dst as moveExportedArchive.
func copyFileVerified(src, dst, wantSHA string) error {
	in, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("opening staged archive: %w", err)
	}
	defer func() { _ = in.Close() }()

	out, tmpPath, err := createExportTemp(dst)
	if err != nil {
		return fmt.Errorf("creating destination archive: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = out.Close()
			_ = os.Remove(tmpPath)
		}
	}()

	h := sha256.New()
	if _, err = io.Copy(io.MultiWriter(out, h), in); err != nil {
		return fmt.Errorf("copying archive: %w", err)
	}
	if err = out.Sync(); err != nil {
		return fmt.Errorf("syncing destination archive: %w", err)
	}
	if err = out.Close(); err != nil {
		return fmt.Errorf("closing destination archive: %w", err)
	}
	if got := hex.EncodeToString(h.Sum(nil)); wantSHA != "" && got != wantSHA {
		return fmt.Errorf("copied archive digest %s does not match export digest %s", got, wantSHA)
	}
	if err = os.Rename(tmpPath, dst); err != nil {
		return fmt.Errorf("moving archive into place: %w", err)
	}
	committed = true
	// The staged copy is removed right after this, so the destination
	// directory entry has to survive a crash on its own. The archive is
	// already in place if this fails, which the message has to say.
	if err = syncParentDir(filepath.Dir(dst)); err != nil {
		return fmt.Errorf("archive is in place at %s but its directory could not be synced: %w", dst, err)
	}
	return nil
}

// writeExportFileAtomic writes the companion digest the same way, so a
// planted symlink at dst.sha256 is replaced rather than written through.
//
// #nosec G304 G703 -- same root-only destination as moveExportedArchive.
func writeExportFileAtomic(path string, data []byte) error {
	out, tmpPath, err := createExportTemp(path)
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			_ = out.Close()
			_ = os.Remove(tmpPath)
		}
	}()

	if _, err = out.Write(data); err != nil {
		return err
	}
	if err = out.Sync(); err != nil {
		return err
	}
	if err = out.Close(); err != nil {
		return err
	}
	if err = os.Rename(tmpPath, path); err != nil {
		return err
	}
	committed = true
	if err = syncParentDir(filepath.Dir(path)); err != nil {
		return fmt.Errorf("%s is in place but its directory could not be synced: %w", path, err)
	}
	return nil
}

// createExportTemp opens a 0600 temporary file in the destination's own
// directory, which is what makes the rename that follows atomic.
//
// #nosec G304 G703 -- same root-only destination as moveExportedArchive.
func createExportTemp(dst string) (*os.File, string, error) {
	out, err := os.CreateTemp(filepath.Dir(dst), "."+filepath.Base(dst)+".csm-*.part")
	if err != nil {
		return nil, "", err
	}
	return out, out.Name(), nil
}
