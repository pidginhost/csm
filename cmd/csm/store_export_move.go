package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
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
	if err := renameExportFile(src, dst); err == nil {
		_ = renameExportFile(src+".sha256", dst+".sha256")
		return nil
	} else if !isCrossDevice(err) {
		return fmt.Errorf("moving archive into place: %w", err)
	}

	if err := copyFileVerified(src, dst, wantSHA); err != nil {
		_ = os.Remove(dst)
		return err
	}
	if companion, err := os.ReadFile(src + ".sha256"); err == nil {
		if err := os.WriteFile(dst+".sha256", companion, 0o600); err != nil {
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

// copyFileVerified copies src to dst, syncs it, and checks the SHA-256 of
// the bytes written against wantSHA (skipped when wantSHA is empty).
//
// #nosec G304 G703 -- same root-only src and dst as moveExportedArchive.
func copyFileVerified(src, dst, wantSHA string) error {
	in, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("opening staged archive: %w", err)
	}
	defer func() { _ = in.Close() }()

	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("creating destination archive: %w", err)
	}
	h := sha256.New()
	if _, err = io.Copy(io.MultiWriter(out, h), in); err != nil {
		_ = out.Close()
		return fmt.Errorf("copying archive: %w", err)
	}
	if err = out.Sync(); err != nil {
		_ = out.Close()
		return fmt.Errorf("syncing destination archive: %w", err)
	}
	if err = out.Close(); err != nil {
		return fmt.Errorf("closing destination archive: %w", err)
	}
	if got := hex.EncodeToString(h.Sum(nil)); wantSHA != "" && got != wantSHA {
		return fmt.Errorf("copied archive digest %s does not match export digest %s", got, wantSHA)
	}
	return nil
}
