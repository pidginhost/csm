//go:build linux

package checks

import (
	"fmt"
	"os"
	"syscall"
)

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
//  3. linkat(/proc/self/fd/N, qPath) creates a hardlink to the inode
//     we opened, by file descriptor, not by path. Even if the attacker
//     swaps the directory entry right now, the quarantined copy still
//     points at the original malware.
//  4. Unlink the source path. Best-effort: if the attacker swapped, we
//     might be deleting their replacement, but the malware is already
//     in quarantine.
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
	// Refuse to quarantine a non-regular file (block, char, socket,
	// FIFO). The detector only flags regular files, so a non-regular
	// shape at this point means someone is trying to move CSM at a
	// device node or pipe.
	if !cur.Mode().IsRegular() {
		return fmt.Errorf("quarantine: refusing non-regular file at %s (mode=%v)", path, cur.Mode())
	}

	// Linkat by fd via /proc/self/fd. The kernel follows the magic
	// link to the inode behind the fd, so the resulting hardlink is
	// guaranteed to point at the inode we hold, not whatever the
	// directory entry currently resolves to.
	procLink := fmt.Sprintf("/proc/self/fd/%d", fd.Fd())
	if err := os.Link(procLink, qPath); err != nil {
		return fmt.Errorf("quarantine: link %s -> %s: %w", path, qPath, err)
	}

	// Unlink the source path. If the attacker swapped right now, we
	// remove their replacement - but the malware is already safe in
	// quarantine via the hardlink we just made. We deliberately do
	// not fail the operation on unlink errors; the operator-visible
	// outcome (file in quarantine, original removed in the common
	// case) is the same.
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "quarantine: unlink source %s failed: %v (file is in quarantine, original may still exist)\n", path, err)
	}
	return nil
}
