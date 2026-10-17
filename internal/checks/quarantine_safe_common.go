package checks

import (
	"bytes"
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

// requireScannedHead checks that the file still starts with the bytes the
// detector scanned. Stat identity cannot see a rewrite within one timestamp
// tick, and the detector reads only a leading window of the file.
func requireScannedHead(fd *os.File, head []byte) error {
	if len(head) == 0 {
		return errors.New("no scanned content to compare")
	}
	current := make([]byte, len(head))
	if _, err := fd.ReadAt(current, 0); err != nil {
		return fmt.Errorf("read scanned window: %w", err)
	}
	if !bytes.Equal(current, head) {
		return errors.New("content differs from the scanned bytes")
	}
	return nil
}

// Test hooks fail a transaction at the two durability boundaries without
// replacing the descriptor-relative operations used in production.
var quarantineBeforeLease = func(string) error { return nil }
var quarantineBeforeCapturedUnlink = func(string) error { return nil }
var quarantineBeforeSourceSync = func(string) error { return nil }

// removeQuarantinedSource removes the detected name once the content sits in
// quarantine. Production Linux capture binds the final identity check and
// unlink to a private descriptor-relative name. A replacement at the original
// name is left alone and the caller is told what completed.
func removeQuarantinedSource(path, qPath string, original os.FileInfo) error {
	return removeQuarantinedSourceMode(path, qPath, original, false)
}

func removeQuarantinedSourceMode(path, qPath string, original os.FileInfo, requireVersion bool) error {
	return removeQuarantinedSourcePlatform(path, qPath, original, requireVersion)
}

func discardUntrustworthyQuarantineCopy(qPath string, cause error) error {
	if err := os.Remove(qPath); err != nil && !os.IsNotExist(err) {
		return errors.Join(cause, err)
	}
	if err := os.Remove(qPath + ".meta"); err != nil && !os.IsNotExist(err) {
		return errors.Join(cause, err)
	}
	if err := quarantinefs.SyncDir(filepath.Dir(qPath)); err != nil {
		return errors.Join(cause, err)
	}
	return refuseFileResponse(cause)
}
