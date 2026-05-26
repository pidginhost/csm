//go:build !linux

package checks

import (
	"errors"
	"fmt"
	"io"
	"os"
	"syscall"
)

// quarantineFileTOCTOUSafe stub for non-Linux build targets. CSM's
// quarantine path only runs on Linux production hosts; this keeps the
// Go module building on macOS and other dev platforms without pulling
// in the Linux-specific /proc/self/fd hardlink trick.
func quarantineFileTOCTOUSafe(path, qPath string, originalInfo os.FileInfo) error {
	if originalInfo == nil {
		return fmt.Errorf("quarantine: missing original stat")
	}
	if originalInfo.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("quarantine: refused symlink at %s", path)
	}
	if err := os.Rename(path, qPath); err != nil {
		if !errors.Is(err, syscall.EXDEV) {
			return fmt.Errorf("quarantine: rename %s -> %s: %w", path, qPath, err)
		}
		if err := copyQuarantineFileByPath(path, qPath); err != nil {
			return fmt.Errorf("quarantine: copy %s -> %s: %w", path, qPath, err)
		}
		if err := os.Remove(path); err != nil {
			_ = os.Remove(qPath)
			return fmt.Errorf("quarantine: unlink source %s: %w", path, err)
		}
	}
	return nil
}

func copyQuarantineFileByPath(path, qPath string) error {
	// #nosec G304 -- non-Linux development fallback for the remediation
	// subject; Linux production uses fd-preserving quarantine.
	src, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = src.Close() }()
	// #nosec G304 G306 -- qPath is generated under the quarantine
	// directory; 0600 keeps cross-device quarantine copies private.
	dst, err := os.OpenFile(qPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	removeCopy := true
	defer func() {
		if removeCopy {
			_ = os.Remove(qPath)
		}
	}()
	if _, err := io.Copy(dst, src); err != nil {
		_ = dst.Close()
		return err
	}
	if err := dst.Close(); err != nil {
		return err
	}
	removeCopy = false
	return nil
}
