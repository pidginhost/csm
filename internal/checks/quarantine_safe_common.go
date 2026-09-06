package checks

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/pidginhost/csm/internal/quarantinefs"
)

type quarantineCompletedWarning struct {
	message string
}

func (w *quarantineCompletedWarning) Error() string {
	return w.message
}

func completedQuarantineWarning(err error) (string, bool) {
	var warning *quarantineCompletedWarning
	if !errors.As(err, &warning) {
		return "", false
	}
	return warning.Error(), true
}

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
func copyQuarantineFileByFD(src *os.File, qPath string, metadata []byte) error {
	if _, err := src.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("seek source: %w", err)
	}
	return quarantinefs.Store(qPath, src, metadata, 0600)
}

var quarantineUnlinkSource = os.Remove
var quarantineSyncSourceDir = quarantinefs.SyncDir

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
			if syncErr := quarantineSyncSourceDir(filepath.Dir(path)); syncErr != nil {
				return fmt.Errorf("quarantine: source vanished but removal is not durable; recovery copy retained at %s: %w", qPath, syncErr)
			}
			return nil
		}
		return fmt.Errorf("quarantine: stat source before unlink %s; recovery copy retained at %s: %w", path, qPath, err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !sameFileIdentity(info, original) {
		return fmt.Errorf("quarantine: source at %s was replaced before unlink; the detected content is kept at %s and the replacement was left in place", path, qPath)
	}
	if !sameContentShape(info, original) {
		// A copy made while the source changed may mix old and new bytes.
		// Keep the live source and discard this untrustworthy recovery copy.
		cause := fmt.Errorf("quarantine: source changed before unlink %s", path)
		if err := os.Remove(qPath); err != nil && !os.IsNotExist(err) {
			return errors.Join(cause, err)
		}
		if err := os.Remove(qPath + ".meta"); err != nil && !os.IsNotExist(err) {
			return errors.Join(cause, err)
		}
		return errors.Join(cause, quarantinefs.SyncDir(filepath.Dir(qPath)))
	}
	if err := quarantineUnlinkSource(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("quarantine: unlink source %s; recovery copy retained at %s: %w", path, qPath, err)
	}
	if err := quarantineSyncSourceDir(filepath.Dir(path)); err != nil {
		return fmt.Errorf("quarantine: source removal is not durable; recovery copy retained at %s, inspect original path %s before retrying: %w", qPath, path, err)
	}
	return nil
}
