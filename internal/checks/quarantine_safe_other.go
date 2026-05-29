//go:build !linux

package checks

import (
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

	// #nosec G304 -- path is the quarantine subject; O_NOFOLLOW plus fd
	// identity verification below fail closed on symlink and inode swaps.
	fd, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return fmt.Errorf("quarantine: open %s: %w", path, err)
	}
	defer func() { _ = fd.Close() }()

	cur, err := fd.Stat()
	if err != nil {
		return fmt.Errorf("quarantine: fstat %s: %w", path, err)
	}
	if !sameFileIdentity(cur, originalInfo) {
		return fmt.Errorf("quarantine: file at %s changed between detection and quarantine (TOCTOU)", path)
	}
	if !sameContentShape(cur, originalInfo) {
		return fmt.Errorf("quarantine: file at %s changed between detection and quarantine (TOCTOU, inode reused)", path)
	}
	if !cur.Mode().IsRegular() {
		return fmt.Errorf("quarantine: refusing non-regular file at %s (mode=%v)", path, cur.Mode())
	}

	if err := copyQuarantineFileByFD(fd, qPath); err != nil {
		return fmt.Errorf("quarantine: copy %s -> %s: %w", path, qPath, err)
	}
	if err := removeQuarantinedSource(path, qPath, cur); err != nil {
		return err
	}
	return nil
}

func sameContentShape(a, b os.FileInfo) bool {
	if a == nil || b == nil {
		return false
	}
	if a.Size() != b.Size() {
		return false
	}
	return a.ModTime().Equal(b.ModTime())
}

func copyQuarantineFileByFD(src *os.File, qPath string) error {
	if _, err := src.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("seek source: %w", err)
	}
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

func removeQuarantinedSource(path, qPath string, original os.FileInfo) error {
	info, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		_ = os.Remove(qPath)
		return fmt.Errorf("quarantine: stat source before unlink %s: %w", path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !sameFileIdentity(info, original) {
		return nil
	}
	if !sameContentShape(info, original) {
		_ = os.Remove(qPath)
		return fmt.Errorf("quarantine: source changed before unlink %s", path)
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		_ = os.Remove(qPath)
		return fmt.Errorf("quarantine: unlink source %s: %w", path, err)
	}
	return nil
}
