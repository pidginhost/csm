//go:build linux

package checks

import (
	"fmt"
	"os"
	"syscall"
)

// var so Linux tests can interleave a source-path mutation after the verified
// fd is open without racing the test process itself.
var quarantineCopyByFD = copyQuarantineFileByFD

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
//  3. Copy from that verified fd into a private, independent quarantine
//     inode. A hardlink is never used: the account could add another name
//     after the initial fstat and keep the quarantine inode writable.
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

	// Always create an independent root-owned copy. Checking st_nlink before a
	// hardlink is not sufficient: the account can add another name after the
	// check and retain write access to the inode placed in quarantine.
	if err := quarantineCopyByFD(fd, qPath); err != nil {
		return fmt.Errorf("quarantine: copy %s -> %s: %w", path, qPath, err)
	}

	if err := removeQuarantinedSource(path, qPath, cur); err != nil {
		return err
	}
	remaining, err := fd.Stat()
	if err != nil {
		return &quarantineCompletedWarning{message: fmt.Sprintf("quarantine: copied %s to %s and removed that name, but could not count surviving hard links: %v", path, qPath, err)}
	}
	if links := fileLinkCount(remaining); links > 0 {
		return &quarantineCompletedWarning{message: fmt.Sprintf("quarantine: copied %s to %s and removed that name, but at least %d other hard link(s) to the same content remain reachable elsewhere", path, qPath, links)}
	}
	return nil
}

// fileLinkCount returns the inode's link count, or 1 when the stat carries
// no platform data.
func fileLinkCount(info os.FileInfo) uint64 {
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		return uint64(st.Nlink) // #nosec G115 -- link count, never negative.
	}
	return 1
}
