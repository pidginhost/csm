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

const (
	maxRestoreEntrySize    = 1 << 30
	maxRestoreManifestSize = 64 << 10
)

var renameRestorePath = os.Rename

// RestoreBackupArchive validates and stages the complete archive before it
// atomically replaces destination paths. If a replacement fails, earlier
// replacements are rolled back. The guarded CLI entry point is responsible
// for proving the daemon is stopped before calling this lower-level helper.
//
// Defends against path traversal and planted symlinks: archive entries
// with `../` components or absolute paths are rejected, and existing
// symlinks under the configured destination trees are not followed.
func RestoreBackupArchive(archive string, dst BackupSources) (err error) {
	stageRoot, err := os.MkdirTemp("", "csm-restore-*")
	if err != nil {
		return fmt.Errorf("creating restore staging directory: %w", err)
	}
	defer os.RemoveAll(stageRoot)
	staged, err := extractBackupArchive(archive, stageRoot)
	if err != nil {
		return err
	}
	return commitBackupRestore(staged, dst)
}

type stagedBackupRestore struct {
	root      string
	hasConfig bool
	hasConf   bool
	hasState  bool
}

func extractBackupArchive(archive, stageRoot string) (_ stagedBackupRestore, err error) {
	staged := stagedBackupRestore{root: stageRoot}
	f, err := os.Open(archive) // #nosec G304 G703 -- operator-supplied archive path.
	if err != nil {
		return staged, err
	}
	defer f.Close()
	gr, err := gzip.NewReader(f)
	if err != nil {
		return staged, err
	}
	defer func() {
		if closeErr := gr.Close(); err == nil && closeErr != nil {
			err = closeErr
		}
	}()
	tr := tar.NewReader(gr)
	seen := make(map[string]struct{})
	manifestSeen := false
	for {
		hdr, nextErr := tr.Next()
		if nextErr == io.EOF {
			if !manifestSeen {
				return staged, errors.New("backup manifest is missing")
			}
			return staged, nil
		}
		if nextErr != nil {
			return staged, nextErr
		}

		if hdr.Typeflag != tar.TypeReg && hdr.Typeflag != tar.TypeDir {
			continue
		}
		if hdr.Typeflag == tar.TypeReg && (hdr.Size < 0 || hdr.Size > maxRestoreEntrySize) {
			return staged, fmt.Errorf("rejecting archive entry %q with size %d", hdr.Name, hdr.Size)
		}

		// Defense in depth: reject path traversal before cleaning so
		// conf.d/../escaped does not collapse into a harmless-looking name.
		rawName := filepath.ToSlash(hdr.Name)
		if unsafeArchiveName(rawName) {
			return staged, fmt.Errorf("rejecting archive entry with unsafe path: %q", hdr.Name)
		}
		clean := path.Clean(rawName)
		if _, exists := seen[clean]; exists {
			return staged, fmt.Errorf("rejecting duplicate archive entry: %q", hdr.Name)
		}
		seen[clean] = struct{}{}
		if hdr.Typeflag == tar.TypeDir {
			switch clean {
			case "conf.d":
				staged.hasConf = true
				if mkdirErr := os.MkdirAll(filepath.Join(stageRoot, "conf.d"), 0o700); mkdirErr != nil {
					return staged, mkdirErr
				}
			case "state":
				staged.hasState = true
				if mkdirErr := os.MkdirAll(filepath.Join(stageRoot, "state"), 0o700); mkdirErr != nil {
					return staged, mkdirErr
				}
			}
			continue
		}
		if clean == "state/"+daemonStateLockFileName {
			continue
		}

		var target, anchor string
		switch {
		case clean == "csm.yaml":
			target = filepath.Join(stageRoot, "csm.yaml")
			anchor = stageRoot
			staged.hasConfig = true
		case strings.HasPrefix(clean, "conf.d/"):
			anchor = filepath.Join(stageRoot, "conf.d")
			target = filepath.Join(anchor, strings.TrimPrefix(clean, "conf.d/"))
			staged.hasConf = true
		case strings.HasPrefix(clean, "state/"):
			anchor = filepath.Join(stageRoot, "state")
			target = filepath.Join(anchor, strings.TrimPrefix(clean, "state/"))
			staged.hasState = true
		case clean == "manifest.txt":
			if hdr.Size > maxRestoreManifestSize {
				return staged, fmt.Errorf("backup manifest exceeds %d bytes", maxRestoreManifestSize)
			}
			manifest := make([]byte, hdr.Size)
			if _, readErr := io.ReadFull(tr, manifest); readErr != nil {
				return staged, fmt.Errorf("reading backup manifest: %w", readErr)
			}
			if !validBackupManifest(manifest) {
				return staged, errors.New("unsupported or invalid backup manifest")
			}
			manifestSeen = true
			continue
		default:
			continue // unknown entries skipped
		}

		out, err := openRestoreTarget(anchor, target)
		if err != nil {
			return staged, fmt.Errorf("rejecting archive entry %q: %w", hdr.Name, err)
		}
		if _, copyErr := io.CopyN(out, tr, hdr.Size); copyErr != nil {
			if closeErr := out.Close(); closeErr != nil {
				return staged, fmt.Errorf("%w (also: close %s: %v)", copyErr, target, closeErr)
			}
			return staged, copyErr
		}
		if closeErr := out.Close(); closeErr != nil {
			return staged, closeErr
		}
	}
}

func validBackupManifest(manifest []byte) bool {
	for _, line := range strings.Split(string(manifest), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if ok && key == "schema" && value == "1" {
			return true
		}
	}
	return false
}

type restoreReplacement struct {
	prepared   string
	target     string
	backup     string
	hadOld     bool
	deleteOnly bool
}

func commitBackupRestore(staged stagedBackupRestore, dst BackupSources) error {
	type candidate struct {
		source     string
		target     string
		isDir      bool
		deleteOnly bool
	}
	var candidates []candidate
	if staged.hasConfig && dst.ConfigPath != "" {
		candidates = append(candidates, candidate{source: filepath.Join(staged.root, "csm.yaml"), target: dst.ConfigPath})
	}
	if staged.hasConf && dst.ConfDir != "" {
		candidates = append(candidates, candidate{source: filepath.Join(staged.root, "conf.d"), target: dst.ConfDir, isDir: true})
	}
	if staged.hasState && dst.StateDir != "" {
		if err := rejectRestoreSymlinks(dst.StateDir); err != nil {
			return err
		}
		stateSource := filepath.Join(staged.root, "state")
		stagedEntries, err := os.ReadDir(stateSource)
		if err != nil {
			return err
		}
		stagedNames := make(map[string]struct{}, len(stagedEntries))
		for _, entry := range stagedEntries {
			stagedNames[entry.Name()] = struct{}{}
			candidates = append(candidates, candidate{
				source: filepath.Join(stateSource, entry.Name()),
				target: filepath.Join(dst.StateDir, entry.Name()),
				isDir:  entry.IsDir(),
			})
		}
		targetEntries, err := os.ReadDir(dst.StateDir) // #nosec G304 -- operator-configured state directory.
		if err != nil && !os.IsNotExist(err) {
			return err
		}
		for _, entry := range targetEntries {
			if entry.Name() == daemonStateLockFileName {
				continue
			}
			if _, exists := stagedNames[entry.Name()]; exists {
				continue
			}
			candidates = append(candidates, candidate{target: filepath.Join(dst.StateDir, entry.Name()), deleteOnly: true})
		}
	}

	replacements := make([]restoreReplacement, 0, len(candidates))
	for _, item := range candidates {
		if err := rejectRestoreSymlinks(item.target); err != nil {
			return err
		}
		prepared := ""
		if !item.deleteOnly {
			var err error
			prepared, err = prepareRestoreReplacement(item.source, item.target, item.isDir)
			if err != nil {
				for _, replacement := range replacements {
					if replacement.prepared != "" {
						_ = os.RemoveAll(replacement.prepared)
					}
				}
				return err
			}
		}
		replacements = append(replacements, restoreReplacement{prepared: prepared, target: item.target, deleteOnly: item.deleteOnly})
	}
	defer func() {
		for _, replacement := range replacements {
			if replacement.prepared != "" {
				_ = os.RemoveAll(replacement.prepared)
			}
		}
	}()

	committed := 0
	for i := range replacements {
		replacement := &replacements[i]
		if _, err := os.Lstat(replacement.target); err == nil {
			backup, reserveErr := reserveRestorePath(filepath.Dir(replacement.target), ".csm-restore-old-*")
			if reserveErr != nil {
				return errors.Join(reserveErr, rollbackRestoreReplacements(replacements[:committed]))
			}
			replacement.backup = backup
			if renameErr := renameRestorePath(replacement.target, replacement.backup); renameErr != nil {
				primary := fmt.Errorf("staging existing restore target %s: %w", replacement.target, renameErr)
				return errors.Join(primary, rollbackRestoreReplacements(replacements[:committed]))
			}
			replacement.hadOld = true
		} else if !os.IsNotExist(err) {
			primary := fmt.Errorf("inspecting restore target %s: %w", replacement.target, err)
			return errors.Join(primary, rollbackRestoreReplacements(replacements[:committed]))
		}
		if replacement.deleteOnly {
			if err := syncParentDir(filepath.Dir(replacement.target)); err != nil {
				var restoreCurrentErr error
				if replacement.hadOld {
					if restoreErr := renameRestorePath(replacement.backup, replacement.target); restoreErr != nil {
						restoreCurrentErr = fmt.Errorf("restoring stale target %s: %w", replacement.target, restoreErr)
					}
				}
				primary := fmt.Errorf("syncing removal of stale restore target %s: %w", replacement.target, err)
				return errors.Join(primary, restoreCurrentErr, rollbackRestoreReplacements(replacements[:committed]))
			}
			committed++
			continue
		}

		if err := renameRestorePath(replacement.prepared, replacement.target); err != nil {
			var restoreCurrentErr error
			if replacement.hadOld {
				if restoreErr := renameRestorePath(replacement.backup, replacement.target); restoreErr != nil {
					restoreCurrentErr = fmt.Errorf("restoring previous target %s: %w", replacement.target, restoreErr)
				} else {
					restoreCurrentErr = syncParentDir(filepath.Dir(replacement.target))
				}
			}
			primary := fmt.Errorf("installing restore target %s: %w", replacement.target, err)
			return errors.Join(primary, restoreCurrentErr, rollbackRestoreReplacements(replacements[:committed]))
		}
		if err := syncParentDir(filepath.Dir(replacement.target)); err != nil {
			var restoreCurrentErr error
			if removeErr := os.RemoveAll(replacement.target); removeErr != nil {
				restoreCurrentErr = fmt.Errorf("removing unsynced restore target %s: %w", replacement.target, removeErr)
			}
			if replacement.hadOld {
				if restoreErr := renameRestorePath(replacement.backup, replacement.target); restoreErr != nil {
					restoreCurrentErr = errors.Join(restoreCurrentErr, fmt.Errorf("restoring previous target %s: %w", replacement.target, restoreErr))
				} else if syncErr := syncParentDir(filepath.Dir(replacement.target)); syncErr != nil {
					restoreCurrentErr = errors.Join(restoreCurrentErr, syncErr)
				}
			}
			primary := fmt.Errorf("syncing restore target %s: %w", replacement.target, err)
			return errors.Join(primary, restoreCurrentErr, rollbackRestoreReplacements(replacements[:committed]))
		}
		committed++
	}
	for _, replacement := range replacements {
		if replacement.hadOld {
			if err := os.RemoveAll(replacement.backup); err != nil {
				return fmt.Errorf("removing previous restore target %s: %w", replacement.backup, err)
			}
			if err := syncParentDir(filepath.Dir(replacement.target)); err != nil {
				return err
			}
		}
	}
	return nil
}

func prepareRestoreReplacement(source, target string, isDir bool) (string, error) {
	parent := filepath.Dir(target)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return "", fmt.Errorf("creating restore parent %s: %w", parent, err)
	}
	if isDir {
		prepared, err := os.MkdirTemp(parent, ".csm-restore-new-*")
		if err != nil {
			return "", err
		}
		if err := copyRestoreTree(source, prepared); err != nil {
			_ = os.RemoveAll(prepared)
			return "", err
		}
		return prepared, nil
	}

	in, err := os.Open(source) // #nosec G304 -- source is under the private restore staging directory.
	if err != nil {
		return "", err
	}
	defer in.Close()
	out, err := os.CreateTemp(parent, ".csm-restore-new-*")
	if err != nil {
		return "", err
	}
	prepared := out.Name()
	ok := false
	defer func() {
		_ = out.Close()
		if !ok {
			_ = os.Remove(prepared)
		}
	}()
	if err := out.Chmod(0o600); err != nil {
		return "", err
	}
	if _, err := io.Copy(out, in); err != nil {
		return "", err
	}
	if err := out.Sync(); err != nil {
		return "", err
	}
	if err := out.Close(); err != nil {
		return "", err
	}
	ok = true
	return prepared, nil
}

func copyRestoreTree(source, target string) error {
	sourceRoot, err := os.OpenRoot(source)
	if err != nil {
		return err
	}
	defer func() { _ = sourceRoot.Close() }()
	return filepath.Walk(source, func(current string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(source, current)
		if err != nil {
			return err
		}
		destination := filepath.Join(target, rel)
		if info.IsDir() {
			return os.MkdirAll(destination, 0o700)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("restore staging contains symlink %s", current)
		}
		in, err := sourceRoot.Open(rel)
		if err != nil {
			return err
		}
		out, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) // #nosec G304 -- destination is under a private sibling staging directory.
		if err != nil {
			_ = in.Close()
			return err
		}
		_, copyErr := io.Copy(out, in)
		closeInErr := in.Close()
		syncOutErr := out.Sync()
		closeOutErr := out.Close()
		if copyErr != nil {
			return copyErr
		}
		if closeInErr != nil {
			return closeInErr
		}
		if syncOutErr != nil {
			return syncOutErr
		}
		return closeOutErr
	})
}

func rejectRestoreSymlinks(target string) error {
	info, err := os.Lstat(target)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspecting restore target %s: %w", target, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("rejecting symlinked restore target %s", target)
	}
	if !info.IsDir() {
		return nil
	}
	return filepath.Walk(target, func(current string, currentInfo os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if currentInfo.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("rejecting symlink beneath restore target: %s", current)
		}
		return nil
	})
}

func reserveRestorePath(parent, pattern string) (string, error) {
	reserved, err := os.CreateTemp(parent, pattern)
	if err != nil {
		return "", err
	}
	name := reserved.Name()
	if err := reserved.Close(); err != nil {
		_ = os.Remove(name)
		return "", err
	}
	if err := os.Remove(name); err != nil {
		return "", err
	}
	return name, nil
}

func rollbackRestoreReplacements(replacements []restoreReplacement) error {
	var rollbackErr error
	for i := len(replacements) - 1; i >= 0; i-- {
		replacement := replacements[i]
		if err := os.RemoveAll(replacement.target); err != nil {
			rollbackErr = errors.Join(rollbackErr, fmt.Errorf("removing restored target %s during rollback: %w", replacement.target, err))
			continue
		}
		if replacement.hadOld {
			if err := renameRestorePath(replacement.backup, replacement.target); err != nil {
				rollbackErr = errors.Join(rollbackErr, fmt.Errorf("restoring previous target %s during rollback: %w", replacement.target, err))
				continue
			}
		}
		if err := syncParentDir(filepath.Dir(replacement.target)); err != nil {
			rollbackErr = errors.Join(rollbackErr, err)
		}
	}
	return rollbackErr
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
