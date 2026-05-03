package main

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

// BackupSources lists the on-disk inputs csm backup includes.
type BackupSources struct {
	ConfigPath string // /opt/csm/csm.yaml
	ConfDir    string // /etc/csm/conf.d/
	StateDir   string // /var/lib/csm/state/
}

// WriteBackupArchive bundles every source path into a tar+gzip file at out.
// State files (bbolt, JSON) are read live; integrity is the operator's
// responsibility - for a clean snapshot, stop the daemon first. Empty or
// non-existent source paths are skipped silently.
func WriteBackupArchive(out string, src BackupSources) error {
	f, err := os.Create(out) // #nosec G304 -- operator-supplied destination
	if err != nil {
		return fmt.Errorf("creating backup: %w", err)
	}
	defer f.Close()
	gw := gzip.NewWriter(f)
	defer gw.Close()
	tw := tar.NewWriter(gw)
	defer tw.Close()

	if src.ConfigPath != "" {
		if err := addFile(tw, src.ConfigPath, "csm.yaml"); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	if src.ConfDir != "" {
		if err := addDir(tw, src.ConfDir, "conf.d"); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	if src.StateDir != "" {
		if err := addDir(tw, src.StateDir, "state"); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	body := fmt.Sprintf("backup_ts=%s\nschema=1\n", time.Now().UTC().Format(time.RFC3339))
	if err := addBytes(tw, "manifest.txt", []byte(body)); err != nil {
		return err
	}
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
	if err := tw.WriteHeader(&tar.Header{Name: name, Size: st.Size(), Mode: 0o600, ModTime: st.ModTime()}); err != nil {
		return err
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

func addDir(tw *tar.Writer, dir, prefix string) error {
	return filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(dir, path)
		return addFile(tw, path, filepath.Join(prefix, rel))
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
	if err := WriteBackupArchive(out, src); err != nil {
		fmt.Fprintf(os.Stderr, "backup failed: %v\n", err)
		os.Exit(1)
	}
	st, _ := os.Stat(out)
	fmt.Printf("backup written: %s (%d bytes)\n", out, st.Size())
}

// isFlag returns true if the argument starts with "-".
func isFlag(s string) bool {
	return len(s) > 0 && s[0] == '-'
}
