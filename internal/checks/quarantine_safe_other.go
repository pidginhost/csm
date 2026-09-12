//go:build !linux

package checks

import (
	"fmt"
	"os"
	"syscall"
)

// Non-Linux builds share the private-copy transaction, without Linux's
// surviving-hardlink warning used by production hosts.
func quarantineFileTOCTOUSafe(path, qPath string, originalInfo os.FileInfo, metadata []byte) error {
	if originalInfo == nil {
		return fmt.Errorf("quarantine: missing original stat")
	}
	if originalInfo.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("quarantine: refused symlink at %s", path)
	}

	// #nosec G304 -- path is the quarantine subject; O_NOFOLLOW plus fd
	// identity verification below fail closed on symlink and inode swaps.
	fd, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return fmt.Errorf("quarantine: open %s: %w", path, fileResponseSourceError(err))
	}
	defer func() { _ = fd.Close() }()

	cur, err := fd.Stat()
	if err != nil {
		return fmt.Errorf("quarantine: fstat %s: %w", path, err)
	}
	if !sameFileIdentity(cur, originalInfo) {
		return fmt.Errorf("quarantine: file at %s changed between detection and quarantine (TOCTOU): %w", path, errFileResponseRefused)
	}
	if !sameContentShape(cur, originalInfo) {
		return fmt.Errorf("quarantine: file at %s changed between detection and quarantine (TOCTOU, inode reused): %w", path, errFileResponseRefused)
	}
	if !cur.Mode().IsRegular() {
		return fmt.Errorf("quarantine: refusing non-regular file at %s (mode=%v)", path, cur.Mode())
	}

	if err := copyQuarantineFileByFD(fd, qPath, metadata); err != nil {
		return fmt.Errorf("quarantine: copy %s -> %s: %w", path, qPath, err)
	}
	if err := removeQuarantinedSource(path, qPath, cur); err != nil {
		return err
	}
	return nil
}
