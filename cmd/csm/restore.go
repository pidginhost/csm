package main

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"syscall"
)

const maxRestoreEntrySize = 1 << 30

// RestoreBackupArchive extracts archive into the destination paths
// supplied. Existing files are overwritten. Caller is responsible for
// stopping the daemon first - we don't try to detect a live bbolt
// handle (the daemon would be holding the lock anyway).
//
// Defends against path traversal: archive entries with `../` components
// or absolute paths are rejected.
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

		if symErr := refuseSymlinkBelow(anchor, target); symErr != nil {
			return fmt.Errorf("rejecting archive entry %q: %w", hdr.Name, symErr)
		}
		if mkdirErr := os.MkdirAll(filepath.Dir(target), 0o700); mkdirErr != nil {
			return mkdirErr
		}
		// O_NOFOLLOW protects against a symlink planted at target itself
		// between the refuseSymlinkBelow probe and the open; refuseSymlinkBelow
		// covers every intermediate component above target.
		out, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_TRUNC|syscall.O_NOFOLLOW, 0o600) // #nosec G304 -- target derived from sanitized archive entry
		if err != nil {
			return err
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

// refuseSymlinkBelow walks the path from anchor down to target and returns
// an error if any existing component is a symlink. Combined with O_NOFOLLOW
// on the final OpenFile this prevents a pre-existing symlink (planted by an
// earlier attacker with write access to the destination tree) from
// redirecting the restored bytes outside the controlled directories.
func refuseSymlinkBelow(anchor, target string) error {
	if anchor == "" {
		return fmt.Errorf("anchor unset for %q", target)
	}
	rel, err := filepath.Rel(anchor, target)
	if err != nil {
		return fmt.Errorf("relative path: %w", err)
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return fmt.Errorf("target %q escapes anchor %q", target, anchor)
	}
	p := anchor
	if info, err := os.Lstat(p); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("anchor %s is a symlink", p)
	}
	for _, seg := range strings.Split(filepath.ToSlash(rel), "/") {
		if seg == "" || seg == "." {
			continue
		}
		p = filepath.Join(p, seg)
		info, err := os.Lstat(p)
		if err != nil {
			if os.IsNotExist(err) {
				return nil
			}
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("refusing to traverse symlink at %s", p)
		}
	}
	return nil
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
	if err := RestoreBackupArchive(archive, dst); err != nil {
		fmt.Fprintf(os.Stderr, "restore failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("restored from %s - restart daemon: systemctl restart csm.service\n", archive)
}
