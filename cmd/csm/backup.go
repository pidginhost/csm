package main

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"time"
)

// BackupSources lists the on-disk inputs csm backup includes.
type BackupSources struct {
	ConfigPath string // main csm.yaml path
	ConfDir    string // /etc/csm/conf.d/
	StateDir   string // /var/lib/csm/state/
}

// WriteBackupArchive bundles every source path into a tar+gzip file at out.
// State files (bbolt, JSON) are read live; integrity is the operator's
// responsibility - for a clean snapshot, stop the daemon first. Empty or
// non-existent source paths are skipped silently.
func WriteBackupArchive(out string, src BackupSources) (err error) {
	outAbs, err := filepath.Abs(out)
	if err != nil {
		return fmt.Errorf("resolving output path: %w", err)
	}
	if src.ConfigPath != "" {
		cfgAbs, cfgErr := filepath.Abs(src.ConfigPath)
		if cfgErr != nil {
			return fmt.Errorf("resolving config path: %w", cfgErr)
		}
		if outAbs == cfgAbs {
			return fmt.Errorf("backup output must not overwrite config file: %s", out)
		}
	}

	f, err := os.Create(out) // #nosec G304 G703 -- operator-supplied backup destination.
	if err != nil {
		return fmt.Errorf("creating backup: %w", err)
	}
	fileClosed := false
	defer func() {
		if !fileClosed {
			if closeErr := f.Close(); err == nil && closeErr != nil {
				err = fmt.Errorf("closing backup: %w", closeErr)
			}
		}
	}()
	gw := gzip.NewWriter(f)
	tw := tar.NewWriter(gw)
	writersClosed := false
	defer func() {
		if !writersClosed {
			_ = tw.Close()
			_ = gw.Close()
		}
	}()

	if src.ConfigPath != "" {
		if err := addFile(tw, src.ConfigPath, "csm.yaml"); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	if src.ConfDir != "" {
		if err := addDir(tw, src.ConfDir, "conf.d", outAbs); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	if src.StateDir != "" {
		if err := addDir(tw, src.StateDir, "state", outAbs); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	body := fmt.Sprintf("backup_ts=%s\nschema=1\n", time.Now().UTC().Format(time.RFC3339))
	if err := addBytes(tw, "manifest.txt", []byte(body)); err != nil {
		return err
	}
	if err := tw.Close(); err != nil {
		return fmt.Errorf("closing tar: %w", err)
	}
	if err := gw.Close(); err != nil {
		return fmt.Errorf("closing gzip: %w", err)
	}
	writersClosed = true
	if err := f.Close(); err != nil {
		return fmt.Errorf("closing backup: %w", err)
	}
	fileClosed = true
	return nil
}

func addFile(tw *tar.Writer, path, name string) error {
	f, err := os.Open(path) // #nosec G304 -- operator-supplied / programmatic walk
	if err != nil {
		return err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return err
	}
	if writeErr := tw.WriteHeader(&tar.Header{Name: name, Size: st.Size(), Mode: 0o600, ModTime: st.ModTime()}); writeErr != nil {
		return writeErr
	}
	_, err = io.Copy(tw, f)
	return err
}

func addBytes(tw *tar.Writer, name string, data []byte) error {
	if err := tw.WriteHeader(&tar.Header{Name: name, Size: int64(len(data)), Mode: 0o600, ModTime: time.Now()}); err != nil {
		return err
	}
	_, err := tw.Write(data)
	return err
}

func addDir(tw *tar.Writer, dir, prefix, excludeAbs string) error {
	return filepath.Walk(dir, func(filePath string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return nil
		}
		if excludeAbs != "" {
			abs, absErr := filepath.Abs(filePath)
			if absErr != nil {
				return absErr
			}
			if abs == excludeAbs {
				return nil
			}
		}
		rel, err := filepath.Rel(dir, filePath)
		if err != nil {
			return err
		}
		return addFile(tw, filePath, path.Join(prefix, filepath.ToSlash(rel)))
	})
}

func runBackup() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "Usage: csm backup <output.tar.gz>")
		os.Exit(1)
	}
	// Find the output path: last non-flag argument after "backup",
	// skipping known two-part flags (--config, --config-dir) and their values.
	knownPairFlags := map[string]bool{"--config": true, "--config-dir": true}
	out := ""
	for i := 2; i < len(os.Args); i++ {
		if knownPairFlags[os.Args[i]] {
			i++ // skip value
			continue
		}
		if !isFlag(os.Args[i]) {
			out = os.Args[i]
			break
		}
	}
	if out == "" {
		fmt.Fprintln(os.Stderr, "Usage: csm backup <output.tar.gz>")
		os.Exit(1)
	}
	cfg, err := tryLoadConfigLite()
	if err != nil {
		fmt.Fprintf(os.Stderr, "csm backup: %v\n", err)
		os.Exit(1)
	}
	src := BackupSources{
		ConfigPath: cfg.ConfigFile,
		ConfDir:    cfg.ConfigDir,
		StateDir:   cfg.StatePath,
	}
	if backupErr := WriteBackupArchive(out, src); backupErr != nil {
		fmt.Fprintf(os.Stderr, "backup failed: %v\n", backupErr)
		os.Exit(1)
	}
	// #nosec G703 -- operator-supplied backup destination; this stats the archive just written.
	st, err := os.Stat(out)
	if err != nil {
		fmt.Fprintf(os.Stderr, "backup written but stat failed: %v\n", err)
		return
	}
	fmt.Printf("backup written: %s (%d bytes)\n", out, st.Size())
}

// isFlag returns true if the argument starts with "-".
func isFlag(s string) bool {
	return len(s) > 0 && s[0] == '-'
}
