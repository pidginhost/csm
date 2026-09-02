package checks

import (
	"fmt"
	"io"
	"os"
)

// sameContentShape verifies that two stats describe a file with the same
// size and modification time. Used as a defence-in-depth check after
// sameFileIdentity passes, because inode reuse on tmpfs / ext4 lets an
// attacker recreate a file under the same path with a fresh ino that
// happens to match the freed slot.
func sameContentShape(a, b os.FileInfo) bool {
	if a == nil || b == nil {
		return false
	}
	if a.Size() != b.Size() {
		return false
	}
	return a.ModTime().Equal(b.ModTime())
}

// copyQuarantineFileByFD copies the already-open source into qPath. The copy
// is created by the daemon (root-owned, 0600), so unlike a hard link it is
// never writable through any name the account still holds.
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

// removeQuarantinedSource unlinks the detected name once the content sits in
// quarantine, only if the name still resolves to the inode that was captured.
// A source that vanished is done. A source that now resolves to something
// else was swapped in by an attacker racing the unlink: the replacement is
// left alone, the captured copy is kept as evidence, and the caller is told
// the remediation did not complete instead of a silent success that left the
// replacement live under the detected name.
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
		return fmt.Errorf("quarantine: source at %s was replaced before unlink; the detected content is kept at %s and the replacement was left in place", path, qPath)
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
