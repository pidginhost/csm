package main

import (
	"archive/tar"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/pidginhost/csm/internal/state"
	"golang.org/x/sys/unix"
)

const maxRestoreEntrySize = 1 << 30

// RestoreBackupArchive extracts archive into the destination paths
// supplied. Existing files are overwritten. Caller is responsible for
// stopping the daemon first - we don't try to detect a live bbolt
// handle (the daemon would be holding the lock anyway).
//
// Defends against path traversal and planted symlinks: archive entries
// with `../` components or absolute paths are rejected, and existing
// symlinks under the configured destination trees are not followed.
func RestoreBackupArchive(archive string, dst BackupSources) (err error) {
	f, err := os.Open(archive) // #nosec G304 G703 -- operator-supplied archive path.
	if err != nil {
		return err
	}
	defer f.Close()
	gr, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := gr.Close(); err == nil && closeErr != nil {
			err = closeErr
		}
	}()
	tr := tar.NewReader(gr)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}

		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		if hdr.Size < 0 || hdr.Size > maxRestoreEntrySize {
			return fmt.Errorf("rejecting archive entry %q with size %d", hdr.Name, hdr.Size)
		}

		// Defense in depth: reject path traversal before cleaning so
		// conf.d/../escaped does not collapse into a harmless-looking name.
		rawName := filepath.ToSlash(hdr.Name)
		if unsafeArchiveName(rawName) {
			return fmt.Errorf("rejecting archive entry with unsafe path: %q", hdr.Name)
		}
		clean := path.Clean(rawName)
		if clean == "state/"+daemonStateLockFileName {
			continue
		}

		var target, anchor string
		switch {
		case clean == "csm.yaml":
			target = dst.ConfigPath
			anchor = filepath.Dir(dst.ConfigPath)
		case strings.HasPrefix(clean, "conf.d/"):
			target = filepath.Join(dst.ConfDir, strings.TrimPrefix(clean, "conf.d/"))
			anchor = dst.ConfDir
		case strings.HasPrefix(clean, "state/"):
			target = filepath.Join(dst.StateDir, strings.TrimPrefix(clean, "state/"))
			anchor = dst.StateDir
		case clean == "manifest.txt":
			continue // metadata only
		default:
			continue // unknown entries skipped
		}
		if target == "" {
			continue // destination path not configured for this entry kind
		}

		out, err := openRestoreTarget(anchor, target)
		if err != nil {
			return fmt.Errorf("rejecting archive entry %q: %w", hdr.Name, err)
		}
		if _, copyErr := io.CopyN(out, tr, hdr.Size); copyErr != nil {
			if closeErr := out.Close(); closeErr != nil {
				return fmt.Errorf("%w (also: close %s: %v)", copyErr, target, closeErr)
			}
			return copyErr
		}
		if closeErr := out.Close(); closeErr != nil {
			return closeErr
		}
	}
}

// openRestoreTarget creates missing directories under anchor and opens target
// through pinned directory descriptors, so a symlink swap under anchor cannot
// redirect the final write outside the configured restore tree.
func openRestoreTarget(anchor, target string) (*os.File, error) {
	if anchor == "" {
		return nil, fmt.Errorf("anchor unset for %q", target)
	}
	rel, err := filepath.Rel(anchor, target)
	if err != nil {
		return nil, fmt.Errorf("relative path: %w", err)
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return nil, fmt.Errorf("target %q escapes anchor %q", target, anchor)
	}
	dirRel, fileName := filepath.Split(rel)
	if fileName == "" || fileName == "." || fileName == ".." {
		return nil, fmt.Errorf("invalid target filename %q", target)
	}

	if mkdirErr := os.MkdirAll(anchor, 0o700); mkdirErr != nil {
		return nil, mkdirErr
	}
	dirFD, err := unix.Open(anchor, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open anchor %s: %w", anchor, err)
	}
	defer func() {
		if dirFD >= 0 {
			_ = unix.Close(dirFD)
		}
	}()

	for _, seg := range strings.Split(filepath.ToSlash(dirRel), "/") {
		if seg == "" || seg == "." {
			continue
		}
		if seg == ".." {
			return nil, fmt.Errorf("invalid parent component in %q", target)
		}
		nextFD, childErr := openRestoreChildDir(dirFD, seg)
		if childErr != nil {
			return nil, childErr
		}
		_ = unix.Close(dirFD)
		dirFD = nextFD
	}

	fd, err := unix.Openat(dirFD, fileName, unix.O_WRONLY|unix.O_CREAT|unix.O_TRUNC|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open target %s: %w", target, err)
	}
	// #nosec G115 -- unix.Openat returns a non-negative fd on success; err
	// already checked above so the int->uintptr conversion cannot truncate.
	return os.NewFile(uintptr(fd), target), nil
}

func openRestoreChildDir(parentFD int, name string) (int, error) {
	fd, err := unix.Openat(parentFD, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err == nil {
		return fd, nil
	}
	if err != unix.ENOENT {
		return -1, fmt.Errorf("open directory %s: %w", name, err)
	}
	if mkdirErr := unix.Mkdirat(parentFD, name, 0o700); mkdirErr != nil && mkdirErr != unix.EEXIST {
		return -1, fmt.Errorf("create directory %s: %w", name, mkdirErr)
	}
	fd, err = unix.Openat(parentFD, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, fmt.Errorf("open directory %s: %w", name, err)
	}
	return fd, nil
}

func unsafeArchiveName(name string) bool {
	if name == "" || strings.HasPrefix(name, "/") {
		return true
	}
	for _, part := range strings.Split(name, "/") {
		if part == ".." {
			return true
		}
	}
	return false
}

// errRestoreDaemonLive mirrors `csm store import`'s refusal: bbolt's
// flock is advisory, so O_TRUNC-extracting state/csm.db under a live
// daemon corrupts both the mmap'd live state and the restored copy.
var errRestoreDaemonLive = errors.New("daemon is running; stop it first (systemctl stop csm)")

// restoreBackupArchiveGuarded refuses while the daemon is live -- before
// archive extraction touches any restored payload -- then extracts.
func restoreBackupArchiveGuarded(archive string, dst BackupSources) error {
	if isDaemonLive() {
		return errRestoreDaemonLive
	}
	stateLock, err := acquireStoppedDaemonStateLock(dst.StateDir)
	if err != nil {
		return err
	}
	if stateLock != nil {
		defer stateLock.Release()
	}
	if isDaemonLive() {
		return errRestoreDaemonLive
	}
	return RestoreBackupArchive(archive, dst)
}

// acquireStoppedDaemonStateLock closes the daemon-starting race that a
// socket-only check misses: the daemon takes this lock before it opens bbolt
// or binds the control socket.
func acquireStoppedDaemonStateLock(stateDir string) (*state.LockFile, error) {
	if stateDir == "" {
		return nil, nil
	}
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return nil, fmt.Errorf("state dir %q: %w", stateDir, err)
	}
	stateLock, err := state.AcquireLock(stateDir)
	if err != nil {
		return nil, fmt.Errorf("%w: state lock: %v", errRestoreDaemonLive, err)
	}
	return stateLock, nil
}

func runRestore() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "Usage: csm restore <archive.tar.gz>")
		os.Exit(1)
	}

	// Parse the archive path skipping known two-part flags (--config, --config-dir).
	var archive string
	skip := false
	for _, arg := range os.Args[2:] {
		if skip {
			skip = false
			continue
		}
		if arg == "--config" || arg == "--config-dir" {
			skip = true
			continue
		}
		if strings.HasPrefix(arg, "-") {
			continue
		}
		archive = arg
		break
	}
	if archive == "" {
		fmt.Fprintln(os.Stderr, "Usage: csm restore <archive.tar.gz>")
		os.Exit(1)
	}

	cfg, err := tryLoadConfigLite()
	if err != nil {
		fmt.Fprintf(os.Stderr, "csm restore: %v\n", err)
		os.Exit(1)
	}
	dst := BackupSources{
		ConfigPath: cfg.ConfigFile,
		ConfDir:    cfg.ConfigDir,
		StateDir:   cfg.StatePath,
	}
	if err := restoreBackupArchiveGuarded(archive, dst); err != nil {
		// Keep the refusal wording aligned with `csm store import`.
		if errors.Is(err, errRestoreDaemonLive) {
			fmt.Fprintf(os.Stderr, "csm restore: %v\n", err)
		} else {
			fmt.Fprintf(os.Stderr, "restore failed: %v\n", err)
		}
		os.Exit(1)
	}
	fmt.Printf("restored from %s - start daemon: systemctl start csm.service\n", archive)
}
