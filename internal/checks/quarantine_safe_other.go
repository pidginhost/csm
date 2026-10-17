//go:build !linux

package checks

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"github.com/pidginhost/csm/internal/quarantinefs"
)

// Non-Linux builds share the private-copy transaction, without Linux's
// surviving-hardlink warning used by production hosts.
func quarantineFileTOCTOUSafe(path, qPath string, originalInfo os.FileInfo, metadata []byte) error {
	return quarantineFileTOCTOUSafeMode(path, qPath, originalInfo, metadata, false, nil)
}

func removeQuarantinedSourcePlatform(path, qPath string, original os.FileInfo, requireVersion bool) error {
	info, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			if syncErr := quarantinefs.SyncDir(filepath.Dir(path)); syncErr != nil {
				return fmt.Errorf("quarantine: source vanished but removal is not durable; recovery copy retained at %s: %w", qPath, syncErr)
			}
			return nil
		}
		return fmt.Errorf("quarantine: stat source before unlink %s; recovery copy retained at %s: %w", path, qPath, fileResponseSourceError(err))
	}
	if info.Mode()&os.ModeSymlink != 0 || !sameFileIdentity(info, original) {
		return refuseFileResponse(fmt.Errorf("quarantine: source at %s was replaced before unlink; the detected content is kept at %s and the replacement was left in place", path, qPath))
	}
	if !sameContentShape(info, original) || requireVersion && !SameFileVersion(info, original) {
		return discardUntrustworthyQuarantineCopy(qPath, fmt.Errorf("quarantine: source changed before unlink %s", path))
	}
	if err := quarantineBeforeCapturedUnlink(path); err != nil {
		return fmt.Errorf("quarantine: unlink source %s; recovery copy retained at %s: %w", path, qPath, err)
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("quarantine: unlink source %s; recovery copy retained at %s: %w", path, qPath, err)
	}
	if err := quarantineBeforeSourceSync(filepath.Dir(path)); err != nil {
		return fmt.Errorf("quarantine: source removal is not durable; recovery copy retained at %s, inspect original path %s before retrying: %w", qPath, path, err)
	}
	if err := quarantinefs.SyncDir(filepath.Dir(path)); err != nil {
		return fmt.Errorf("quarantine: source removal is not durable; recovery copy retained at %s, inspect original path %s before retrying: %w", qPath, path, err)
	}
	return nil
}

func quarantineFileVersionedTOCTOUSafe(path, qPath string, originalInfo os.FileInfo, metadata, scannedHead []byte) error {
	return quarantineFileTOCTOUSafeMode(path, qPath, originalInfo, metadata, true, scannedHead)
}

func quarantineFileVersionedTOCTOUSafeFD(path, qPath string, originalInfo os.FileInfo, metadata []byte, sourceFD int, scannedHead []byte) error {
	_ = sourceFD
	return quarantineFileVersionedTOCTOUSafe(path, qPath, originalInfo, metadata, scannedHead)
}

func quarantineFileTOCTOUSafeMode(path, qPath string, originalInfo os.FileInfo, metadata []byte, requireVersion bool, scannedHead []byte) error {
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
		return refuseFileResponse(fmt.Errorf("quarantine: file at %s changed between detection and quarantine (TOCTOU)", path))
	}
	if !sameContentShape(cur, originalInfo) || requireVersion && !SameFileVersion(cur, originalInfo) {
		return refuseFileResponse(fmt.Errorf("quarantine: file at %s changed between detection and quarantine (TOCTOU, inode reused)", path))
	}
	if !cur.Mode().IsRegular() {
		return fmt.Errorf("quarantine: refusing non-regular file at %s (mode=%v)", path, cur.Mode())
	}
	if requireVersion {
		if err := requireScannedHead(fd, scannedHead); err != nil {
			return refuseFileResponse(fmt.Errorf("quarantine: file at %s changed before atomic capture: %w", path, err))
		}
	}

	if err := copyQuarantineFileByFD(fd, qPath, metadata); err != nil {
		return fmt.Errorf("quarantine: copy %s -> %s: %w", path, qPath, err)
	}
	if requireVersion {
		err = removeQuarantinedSourceMode(path, qPath, cur, true)
	} else {
		err = removeQuarantinedSource(path, qPath, cur)
	}
	if err != nil {
		return err
	}
	return nil
}
