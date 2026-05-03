package main

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// RestoreBackupArchive extracts archive into the destination paths
// supplied. Existing files are overwritten. Caller is responsible for
// stopping the daemon first - we don't try to detect a live bbolt
// handle (the daemon would be holding the lock anyway).
//
// Defends against path traversal: archive entries with `../` components
// or absolute paths are rejected.
func RestoreBackupArchive(archive string, dst BackupSources) error {
	f, err := os.Open(archive) // #nosec G304 -- operator-supplied archive path
	if err != nil {
		return err
	}
	defer f.Close()
	gr, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer gr.Close()
	tr := tar.NewReader(gr)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}

		// Defense in depth: reject path traversal.
		clean := filepath.ToSlash(filepath.Clean(hdr.Name))
		if strings.HasPrefix(clean, "/") || strings.HasPrefix(clean, "../") || strings.Contains(clean, "/../") {
			return fmt.Errorf("rejecting archive entry with unsafe path: %q", hdr.Name)
		}

		var target string
		switch {
		case clean == "csm.yaml":
			target = dst.ConfigPath
		case strings.HasPrefix(clean, "conf.d/"):
			target = filepath.Join(dst.ConfDir, strings.TrimPrefix(clean, "conf.d/"))
		case strings.HasPrefix(clean, "state/"):
			target = filepath.Join(dst.StateDir, strings.TrimPrefix(clean, "state/"))
		case clean == "manifest.txt":
			continue // metadata only
		default:
			continue // unknown entries skipped
		}
		if target == "" {
			continue // destination path not configured for this entry kind
		}

		if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
			return err
		}
		out, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600) // #nosec G304 -- target derived from sanitized archive entry
		if err != nil {
			return err
		}
		// Limit copy to a sane bound to defend against tar bombs.
		if _, err := io.CopyN(out, tr, 1<<30); err != nil && err != io.EOF {
			out.Close()
			return err
		}
		out.Close()
	}
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
