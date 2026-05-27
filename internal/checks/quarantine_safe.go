//go:build linux

package checks

import (
	"fmt"
	"io"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

// var (not const) so Linux tests can force EXDEV without depending on
// the host's filesystem layout.
var quarantineLinkByFD = linkQuarantineFileByFD

// quarantineFileTOCTOUSafe moves a single regular file into quarantine in
// a way that defends against the classic detect-then-quarantine race: an
// attacker who controls the directory can swap a legitimate file in
// between Lstat and Rename, tricking CSM into moving the wrong file out
// of the user's home. The defence:
//
//  1. Open the path with O_RDONLY|O_NOFOLLOW. Symlinks are refused at
//     the kernel level; the fd is bound to the inode that existed at
//     open time.
//  2. Fstat the fd and verify it still matches the inode we detected
//     earlier (sameFileIdentity). A late swap loses here.
//  3. linkat(/proc/self/fd/N, qPath, AT_SYMLINK_FOLLOW) creates a
//     hardlink to the inode we opened, by file descriptor, not by
//     path. If hardlinking is unavailable, copy from the same open
//     fd instead of reopening by path.
//  4. Unlink the source path only if it still resolves to the inode
//     we quarantined. If an attacker swapped in a replacement after
//     step 2, leave that replacement alone.
//
// Returns nil on success. Errors describe what failed; callers should
// not retry blindly because a failure usually means the file moved.
func quarantineFileTOCTOUSafe(path, qPath string, originalInfo os.FileInfo) error {
	if originalInfo == nil {
		return fmt.Errorf("quarantine: missing original stat")
	}
	if originalInfo.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("quarantine: refused symlink at %s", path)
	}

	// O_NOFOLLOW makes open() fail with ELOOP if path resolved to a
	// symlink in the final component; combined with the earlier Lstat
	// rejection above, this closes the symlink-swap variant.
	// #nosec G304 -- path is the quarantine subject; O_NOFOLLOW plus
	// fd identity verification below fail closed on symlink and inode swaps.
	fd, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return fmt.Errorf("quarantine: open %s: %w", path, err)
	}
	defer fd.Close()

	// Re-stat the open fd and confirm the inode matches what we
	// detected. The race window between Lstat and OpenFile is narrow
	// but real - an attacker who hits it gets caught here.
	cur, err := fd.Stat()
	if err != nil {
		return fmt.Errorf("quarantine: fstat %s: %w", path, err)
	}
	if !sameFileIdentity(cur, originalInfo) {
		return fmt.Errorf("quarantine: file at %s changed between detection and quarantine (TOCTOU)", path)
	}
	// Defence against inode reuse: on busy tmpfs / ext4 mounts the kernel
	// can hand out the freed inode to whatever the attacker wrote next.
	// A matching inode is necessary but not sufficient — also require the
	// content shape (size + mtime) to match what the detector recorded.
	if !sameContentShape(cur, originalInfo) {
		return fmt.Errorf("quarantine: file at %s changed between detection and quarantine (TOCTOU, inode reused)", path)
	}
	// Refuse to quarantine a non-regular file (block, char, socket,
	// FIFO). The detector only flags regular files, so a non-regular
	// shape at this point means someone is trying to move CSM at a
	// device node or pipe.
	if !cur.Mode().IsRegular() {
		return fmt.Errorf("quarantine: refusing non-regular file at %s (mode=%v)", path, cur.Mode())
	}

	if err := quarantineLinkByFD(fd, qPath); err != nil {
		if err := copyQuarantineFileByFD(fd, qPath); err != nil {
			return fmt.Errorf("quarantine: copy %s -> %s: %w", path, qPath, err)
		}
	}

	if err := removeQuarantinedSource(path, qPath, cur); err != nil {
		return err
	}
	return nil
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

func linkQuarantineFileByFD(fd *os.File, qPath string) error {
	procLink := fmt.Sprintf("/proc/self/fd/%d", fd.Fd())
	return unix.Linkat(unix.AT_FDCWD, procLink, unix.AT_FDCWD, qPath, unix.AT_SYMLINK_FOLLOW)
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
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		_ = os.Remove(qPath)
		return fmt.Errorf("quarantine: unlink source %s: %w", path, err)
	}
	return nil
}
