//go:build linux

package checks

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/pidginhost/csm/internal/safepath"
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
//  3. Take an exclusive Linux file lease so a pre-open writer refuses the
//     action and a later open cannot change content before removal.
//  4. Copy from that verified fd into a private, independent quarantine
//     inode. A hardlink is never used: the account could add another name
//     after the initial fstat and keep the quarantine inode writable.
//     Persist the copy, metadata, and quarantine directory before unlinking.
//  5. Atomically move the source name into a private directory on the same
//     filesystem, validate the captured inode, and unlink only that private
//     name. A replacement created at the original name is left alone.
//
// Returns nil on success. Errors describe what failed; callers should
// not retry blindly because a failure usually means the file moved.
func quarantineFileTOCTOUSafe(path, qPath string, originalInfo os.FileInfo, metadata []byte) error {
	return quarantineFileTOCTOUSafeMode(path, qPath, originalInfo, metadata, false, -1)
}

func quarantineFileVersionedTOCTOUSafe(path, qPath string, originalInfo os.FileInfo, metadata []byte) error {
	return quarantineFileVersionedTOCTOUSafeFD(path, qPath, originalInfo, metadata, -1)
}

func quarantineFileVersionedTOCTOUSafeFD(path, qPath string, originalInfo os.FileInfo, metadata []byte, sourceFD int) error {
	return quarantineFileTOCTOUSafeMode(path, qPath, originalInfo, metadata, true, sourceFD)
}

func quarantineFileTOCTOUSafeMode(path, qPath string, originalInfo os.FileInfo, metadata []byte, requireVersion bool, sourceFD int) error {
	if originalInfo == nil {
		return fmt.Errorf("quarantine: missing original stat")
	}
	if originalInfo.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("quarantine: refused symlink at %s", path)
	}

	// Pin the source directory before opening the file. Later capture uses the
	// same descriptor, so renaming a tenant-controlled parent cannot redirect
	// the unlink transaction to a different directory.
	source, err := safepath.OpenDirNoFollow(filepath.Dir(path))
	if err != nil {
		return fmt.Errorf("quarantine: open source directory for %s: %w", path, err)
	}
	defer func() { _ = source.Close() }()
	fd, err := openQuarantineSource(source, filepath.Base(path), sourceFD)
	if err != nil {
		return fmt.Errorf("quarantine: open %s: %w", path, fileResponseSourceError(err))
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
		return refuseFileResponse(fmt.Errorf("quarantine: file at %s changed between detection and quarantine (TOCTOU)", path))
	}
	// Defence against inode reuse: on busy tmpfs / ext4 mounts the kernel
	// can hand out the freed inode to whatever the attacker wrote next.
	// A matching inode is necessary but not sufficient; also require the
	// content shape (size + mtime) to match what the detector recorded.
	if !sameContentShape(cur, originalInfo) || requireVersion && !SameFileVersion(cur, originalInfo) {
		return refuseFileResponse(fmt.Errorf("quarantine: file at %s changed between detection and quarantine (TOCTOU, inode reused)", path))
	}
	// Refuse to quarantine a non-regular file (block, char, socket,
	// FIFO). The detector only flags regular files, so a non-regular
	// shape at this point means someone is trying to move CSM at a
	// device node or pipe.
	if !cur.Mode().IsRegular() {
		return fmt.Errorf("quarantine: refusing non-regular file at %s (mode=%v)", path, cur.Mode())
	}
	if prepareErr := quarantineBeforeLease(path); prepareErr != nil {
		return fmt.Errorf("quarantine: prepare stable content for %s: %w", path, prepareErr)
	}
	if leaseErr := acquireQuarantineLease(fd); leaseErr != nil {
		return refuseFileResponse(fmt.Errorf("quarantine: cannot hold stable content for %s while another descriptor is open: %w", path, leaseErr))
	}
	defer releaseQuarantineLease(fd)
	stable, err := fd.Stat()
	if err != nil {
		return fmt.Errorf("quarantine: fstat stable source %s: %w", path, err)
	}
	versionChanged := !SameFileVersion(stable, originalInfo)
	if !sameFileIdentity(stable, originalInfo) || !sameContentShape(stable, originalInfo) || versionChanged && (requireVersion || fileLinkCount(stable) <= 1) {
		return refuseFileResponse(fmt.Errorf("quarantine: file at %s changed before atomic capture", path))
	}
	cur = stable

	// Always create an independent root-owned copy. Checking st_nlink before a
	// hardlink is not sufficient: the account can add another name after the
	// check and retain write access to the inode placed in quarantine.
	if err = quarantineCopyByFD(fd, qPath, metadata); err != nil {
		return fmt.Errorf("quarantine: copy %s -> %s: %w", path, qPath, err)
	}

	err = removeQuarantinedSourcePinned(source, filepath.Base(path), path, qPath, cur, requireVersion, fd)
	if err != nil {
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

func removeQuarantinedSourcePlatform(path, qPath string, original os.FileInfo, requireVersion bool) error {
	source, err := safepath.OpenDirNoFollow(filepath.Dir(path))
	if err != nil {
		return fmt.Errorf("quarantine: open source directory for %s: %w", path, err)
	}
	defer func() { _ = source.Close() }()
	fd, err := source.OpenFile(filepath.Base(path), os.O_RDONLY, 0)
	if err != nil {
		return fmt.Errorf("quarantine: open %s: %w", path, fileResponseSourceError(err))
	}
	defer fd.Close()
	opened, err := fd.Stat()
	if err != nil {
		return fmt.Errorf("quarantine: fstat %s: %w", path, err)
	}
	if !sameFileIdentity(opened, original) {
		return refuseFileResponse(fmt.Errorf("quarantine: source at %s was replaced before stable-content removal; the detected content is kept at %s and the replacement was left in place", path, qPath))
	}
	versionChanged := !SameFileVersion(opened, original)
	if !sameContentShape(opened, original) || versionChanged && (requireVersion || fileLinkCount(opened) <= 1) {
		return discardUntrustworthyQuarantineCopy(qPath, fmt.Errorf("quarantine: source changed before stable-content removal %s", path))
	}
	if err := acquireQuarantineLease(fd); err != nil {
		return refuseFileResponse(fmt.Errorf("quarantine: cannot hold stable content for %s while another descriptor is open: %w", path, err))
	}
	defer releaseQuarantineLease(fd)
	return removeQuarantinedSourcePinned(source, filepath.Base(path), path, qPath, original, requireVersion, fd)
}

// removeQuarantinedSourcePinned atomically captures the live directory entry
// into a private same-filesystem directory before checking and removing it.
// Validation and unlink therefore operate on one name that tenant writers
// cannot swap between syscalls.
func removeQuarantinedSourcePinned(source *safepath.Dir, sourceName, path, qPath string, original os.FileInfo, requireVersion bool, leased *os.File) error {
	currentParent, err := safepath.OpenDirNoFollow(filepath.Dir(path))
	if err != nil {
		return refuseFileResponse(fmt.Errorf("quarantine: source parent changed before atomic capture %s; recovery copy retained at %s: %w", path, qPath, err))
	}
	sameParent, compareErr := source.SameFile(currentParent)
	_ = currentParent.Close()
	if compareErr != nil {
		return refuseFileResponse(fmt.Errorf("quarantine: source parent changed before atomic capture %s; recovery copy retained at %s: %v", path, qPath, compareErr))
	}
	if !sameParent {
		return refuseFileResponse(fmt.Errorf("quarantine: source parent changed before atomic capture %s; recovery copy retained at %s", path, qPath))
	}
	beforeCapture, err := source.Lstat(sourceName)
	if err != nil {
		if os.IsNotExist(err) {
			if syncErr := source.Sync(); syncErr != nil {
				return fmt.Errorf("quarantine: source vanished but removal is not durable; recovery copy retained at %s: %w", qPath, syncErr)
			}
			return nil
		}
		return fmt.Errorf("quarantine: stat source before atomic capture %s; recovery copy retained at %s: %w", path, qPath, fileResponseSourceError(err))
	}
	if beforeCapture.Mode()&os.ModeSymlink != 0 || !sameFileIdentity(beforeCapture, original) {
		return refuseFileResponse(fmt.Errorf("quarantine: source at %s was replaced before atomic capture; the detected content is kept at %s and the replacement was left in place", path, qPath))
	}
	// A generic quarantine can accept a new hard link because the surviving
	// name keeps the inode recoverable. Realtime PHP response requires the exact
	// scanned version, including ctime, before any namespace mutation.
	versionChanged := !SameFileVersion(beforeCapture, original)
	if !sameContentShape(beforeCapture, original) || versionChanged && (requireVersion || fileLinkCount(beforeCapture) <= 1) {
		return discardUntrustworthyQuarantineCopy(qPath, fmt.Errorf("quarantine: source changed before atomic capture %s", path))
	}
	if leaseErr := requireQuarantineLease(leased); leaseErr != nil {
		return discardUntrustworthyQuarantineCopy(qPath, fmt.Errorf("quarantine: stable content lease broke before atomic capture %s: %w", path, leaseErr))
	}

	stage, stageName, err := source.CreatePrivateTemp()
	if err != nil {
		return fmt.Errorf("quarantine: create private source capture for %s: %w", path, err)
	}
	keepStage := false
	defer func() {
		_ = stage.Close()
		if !keepStage {
			_ = source.RemoveDir(stageName)
		}
	}()

	const capturedName = "captured"
	if err := source.RenameTo(sourceName, stage, capturedName); err != nil {
		if os.IsNotExist(err) {
			if syncErr := source.Sync(); syncErr != nil {
				return fmt.Errorf("quarantine: source vanished but removal is not durable; recovery copy retained at %s: %w", qPath, syncErr)
			}
			return nil
		}
		return fmt.Errorf("quarantine: capture source before unlink %s; recovery copy retained at %s: %w", path, qPath, fileResponseSourceError(err))
	}

	captured, statErr := stage.Lstat(capturedName)
	identityOK := statErr == nil && captured.Mode()&os.ModeSymlink == 0 && sameFileIdentity(captured, original)
	shapeOK := identityOK && sameContentShape(captured, original)
	if !shapeOK {
		cause := fmt.Errorf("quarantine: source at %s was replaced before atomic capture", path)
		if identityOK {
			cause = fmt.Errorf("quarantine: source changed before atomic capture %s", path)
		}
		if err := restoreCapturedSource(stage, capturedName, source, sourceName); err != nil {
			recovery, preserveErr := preserveDisplacedSource(stage, capturedName, qPath, path, captured)
			if preserveErr != nil {
				keepStage = true
				return fmt.Errorf("%w; displaced entry retained in private source directory %s after rollback failed: %v", cause, stageName, errors.Join(err, preserveErr))
			}
			if syncErr := source.Sync(); syncErr != nil {
				return fmt.Errorf("%w; displaced entry retained at %s but source directory sync failed: %v", cause, recovery, syncErr)
			}
			return refuseFileResponse(fmt.Errorf("%w; displaced entry retained at %s because the source name was recreated", cause, recovery))
		}
		if syncErr := errors.Join(stage.Sync(), source.Sync()); syncErr != nil {
			return fmt.Errorf("%w; restored source sync failed: %v", cause, syncErr)
		}
		if identityOK {
			return discardUntrustworthyQuarantineCopy(qPath, cause)
		}
		return refuseFileResponse(fmt.Errorf("%w; the detected content is kept at %s and the replacement was restored", cause, qPath))
	}

	if err := quarantineBeforeCapturedUnlink(path); err != nil {
		if rollbackErr := restoreCapturedSource(stage, capturedName, source, sourceName); rollbackErr != nil {
			keepStage = true
			return fmt.Errorf("quarantine: unlink source %s failed; captured source retained in private directory %s and recovery copy retained at %s: %w", path, stageName, qPath, errors.Join(err, rollbackErr))
		}
		if syncErr := errors.Join(stage.Sync(), source.Sync()); syncErr != nil {
			return fmt.Errorf("quarantine: unlink source %s failed and restored source sync failed; recovery copy retained at %s: %w", path, qPath, errors.Join(err, syncErr))
		}
		return fmt.Errorf("quarantine: unlink source %s; recovery copy retained at %s: %w", path, qPath, err)
	}
	if err := requireQuarantineLease(leased); err != nil {
		cause := fmt.Errorf("quarantine: stable content lease broke before unlink %s: %w", path, err)
		if rollbackErr := restoreCapturedSource(stage, capturedName, source, sourceName); rollbackErr != nil {
			keepStage = true
			return fmt.Errorf("%w; captured source retained in private directory %s and recovery copy retained at %s: %v", cause, stageName, qPath, rollbackErr)
		}
		if syncErr := errors.Join(stage.Sync(), source.Sync()); syncErr != nil {
			return fmt.Errorf("%w; restored source sync failed and recovery copy retained at %s: %v", cause, qPath, syncErr)
		}
		return discardUntrustworthyQuarantineCopy(qPath, cause)
	}
	if err := stage.Remove(capturedName); err != nil {
		keepStage = true
		return fmt.Errorf("quarantine: unlink captured source %s; private source retained in %s and recovery copy retained at %s: %w", path, stageName, qPath, err)
	}
	if err := stage.Sync(); err != nil {
		return fmt.Errorf("quarantine: source removal is not durable inside private capture; recovery copy retained at %s: %w", qPath, err)
	}
	if err := quarantineBeforeSourceSync(filepath.Dir(path)); err != nil {
		return fmt.Errorf("quarantine: source removal is not durable; recovery copy retained at %s, inspect original path %s before retrying: %w", qPath, path, err)
	}
	if err := source.Sync(); err != nil {
		return fmt.Errorf("quarantine: source removal is not durable; recovery copy retained at %s, inspect original path %s before retrying: %w", qPath, path, err)
	}
	if _, err := source.Lstat(sourceName); err == nil || !os.IsNotExist(err) {
		return &quarantineCompletedWarning{message: fmt.Sprintf("quarantine: removed the captured file at %s, but another entry now occupies that name; recovery copy retained at %s", path, qPath)}
	}
	return nil
}

func openQuarantineSource(source *safepath.Dir, name string, sourceFD int) (*os.File, error) {
	if sourceFD < 0 {
		return source.OpenFile(name, os.O_RDONLY, 0)
	}
	dup, err := unix.FcntlInt(uintptr(sourceFD), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(dup), name), nil
}

func acquireQuarantineLease(file *os.File) error {
	_, err := unix.FcntlInt(file.Fd(), unix.F_SETLEASE, unix.F_WRLCK)
	return err
}

func requireQuarantineLease(file *os.File) error {
	lease, err := unix.FcntlInt(file.Fd(), unix.F_GETLEASE, 0)
	if err != nil {
		return err
	}
	if lease != unix.F_WRLCK {
		return errors.New("exclusive lease is no longer held")
	}
	return nil
}

func releaseQuarantineLease(file *os.File) {
	_, _ = unix.FcntlInt(file.Fd(), unix.F_SETLEASE, unix.F_UNLCK)
}

func restoreCapturedSource(stage *safepath.Dir, capturedName string, source *safepath.Dir, sourceName string) error {
	return stage.RenameTo(capturedName, source, sourceName)
}

func preserveDisplacedSource(stage *safepath.Dir, capturedName, qPath, path string, info os.FileInfo) (string, error) {
	if info == nil || !info.Mode().IsRegular() {
		return "", errors.New("displaced entry is not a regular file")
	}
	file, err := stage.OpenFile(capturedName, os.O_RDONLY, 0)
	if err != nil {
		return "", err
	}
	defer file.Close()
	meta := quarantineMetadata(path, info, "Source replacement preserved during quarantine race")
	metadata, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return "", err
	}
	recovery := newQuarantinePath(filepath.Dir(qPath), path+".displaced")
	if err := copyQuarantineFileByFD(file, recovery, metadata); err != nil {
		return "", err
	}
	if err := stage.Remove(capturedName); err != nil {
		return recovery, err
	}
	if err := stage.Sync(); err != nil {
		return recovery, err
	}
	return recovery, nil
}

// fileLinkCount returns the inode's link count, or 1 when the stat carries
// no platform data.
func fileLinkCount(info os.FileInfo) uint64 {
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		return uint64(st.Nlink) // #nosec G115 -- link count, never negative.
	}
	return 1
}
