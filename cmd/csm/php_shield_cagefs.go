package main

import (
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"
)

var cagefsMountPointsPath = "/etc/cagefs/cagefs.mp"

// ensurePHPShieldRuntimePaths prepares the root-owned socket directory and
// archive before making the directory reachable inside CageFS.
func ensurePHPShieldRuntimePaths() error {
	if err := ensurePHPShieldEventLog(); err != nil {
		return err
	}
	if err := ensurePHPShieldCageFSMount(); err != nil {
		return fmt.Errorf("configuring PHP Shield for CageFS: %w", err)
	}
	return nil
}

// ensurePHPShieldCageFSMount registers the Shield event tree as a shared CageFS
// mount. The directory is not tenant-writable; PHP processes can only send to
// the daemon-owned datagram socket, and the archive remains root-only.
//
// This function deliberately does not run cagefsctl --remount-all. CloudLinux
// documents that command as killing every current process in every cage, which
// is an unacceptable side effect for csm install/enable on a busy shared host.
// The operator can apply the new mount during a maintenance window. If CageFS
// is disabled, leaving the configuration ready for its next enable is harmless.
func ensurePHPShieldCageFSMount() (retErr error) {
	// Open before reading, then hold an advisory lock across the idempotency
	// check and append. Cooperating CSM invocations cannot add duplicates. The
	// append itself is one newline-delimited O_APPEND write, so successful
	// writes from an unrelated vendor cannot interleave with this record. A
	// leading newline separates a preceding unterminated vendor record. If the
	// filesystem reports a short write, a best-effort newline narrows the window
	// in which a later non-locking writer could join the incomplete CSM record.
	// #nosec G304 -- fixed CageFS configuration path, overridden only in tests.
	f, err := os.OpenFile(cagefsMountPointsPath, os.O_RDWR|os.O_APPEND|syscall.O_NOFOLLOW, 0)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("opening CageFS mount points: %w", err)
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return fmt.Errorf("checking CageFS mount points: %w", err)
	}
	if !info.Mode().IsRegular() {
		_ = f.Close()
		return fmt.Errorf("CageFS mount-points file is not a regular file")
	}
	defer func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		if closeErr := f.Close(); closeErr != nil && retErr == nil {
			retErr = fmt.Errorf("closing CageFS mount points: %w", closeErr)
		}
	}()

	if lockErr := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); lockErr != nil {
		return fmt.Errorf("locking CageFS mount points: %w", lockErr)
	}
	if _, seekErr := f.Seek(0, io.SeekStart); seekErr != nil {
		return fmt.Errorf("seeking CageFS mount points: %w", seekErr)
	}
	data, err := io.ReadAll(f)
	if err != nil {
		return fmt.Errorf("reading CageFS mount points: %w", err)
	}
	kinds := cagefsMountKindsForPath(string(data), phpShieldEventDir)
	if len(kinds) > 0 {
		for _, kind := range kinds {
			if kind != cagefsMountShared && kind != cagefsMountReadOnly {
				return fmt.Errorf("existing CageFS entry for %s is %s; PHP Shield requires a shared-source mount", phpShieldEventDir, kind)
			}
		}
		return nil
	}

	entry := "\n" + phpShieldEventDir + "\n"
	if err := appendCageFSMountEntry(f, entry); err != nil {
		return fmt.Errorf("adding PHP Shield event dir to CageFS mount points: %w", err)
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("syncing CageFS mount points: %w", err)
	}
	fmt.Fprintln(os.Stderr, "  CageFS mount registered; if CageFS is enabled, apply it in an "+
		"operator-scheduled cagefsctl --remount-all maintenance window")
	return nil
}

// appendCageFSMountEntry uses one write for the normal case so another
// O_APPEND writer cannot interleave bytes with the record. If the filesystem
// reports a short write, add a best-effort separator before returning the
// original error. Writers that ignore our advisory lock can still race this
// recovery path, so callers must treat any short write as configuration damage.
func appendCageFSMountEntry(w io.StringWriter, entry string) error {
	n, err := w.WriteString(entry)
	if n == len(entry) {
		return err
	}
	if err == nil {
		err = io.ErrShortWrite
	}
	terminateN, terminateErr := w.WriteString("\n")
	if terminateErr != nil {
		return fmt.Errorf("%w; terminating partial entry: %v", err, terminateErr)
	}
	if terminateN != 1 {
		return fmt.Errorf("%w; terminating partial entry: %v", err, io.ErrShortWrite)
	}
	return err
}

type cagefsMountKind string

const (
	cagefsMountShared   cagefsMountKind = "shared"
	cagefsMountReadOnly cagefsMountKind = "read-only"
	cagefsMountPerUser  cagefsMountKind = "per-user"
	cagefsMountByUID    cagefsMountKind = "split-by-UID"
	cagefsMountByName   cagefsMountKind = "split-by-name"
)

// cagefsMountForPath finds an exact CageFS mount-point entry. Inline comments
// and trailing whitespace are ignored, but a longer path never matches dir.
// Only @ entries carry a comma-separated mode.
func cagefsMountForPath(contents, dir string) (cagefsMountKind, bool) {
	kinds := cagefsMountKindsForPath(contents, dir)
	if len(kinds) == 0 {
		return "", false
	}
	return kinds[0], true
}

func cagefsMountKindsForPath(contents, dir string) []cagefsMountKind {
	var kinds []cagefsMountKind
	for _, raw := range strings.Split(contents, "\n") {
		line, _, _ := strings.Cut(raw, "#")
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		kind := cagefsMountShared
		switch line[0] {
		case '!':
			kind, line = cagefsMountReadOnly, line[1:]
		case '@':
			kind, line = cagefsMountPerUser, line[1:]
		case '*':
			kind, line = cagefsMountByUID, line[1:]
		case '%':
			kind, line = cagefsMountByName, line[1:]
		}
		line = strings.TrimSpace(line)
		if kind == cagefsMountPerUser {
			line, _, _ = strings.Cut(line, ",")
			line = strings.TrimSpace(line)
		}
		if line == dir {
			kinds = append(kinds, kind)
		}
	}
	return kinds
}
