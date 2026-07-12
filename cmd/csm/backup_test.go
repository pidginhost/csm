package main

import (
	"archive/tar"
	"compress/gzip"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/pidginhost/csm/internal/state"
)

func TestBackupArchive_IncludesConfigAndConfDir(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "csm.yaml")
	confd := filepath.Join(dir, "conf.d")
	state := filepath.Join(dir, "state")
	for _, p := range []string{confd, state} {
		if err := os.MkdirAll(p, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(cfgPath, []byte("hostname: t\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(confd, "10.yaml"), []byte("hostname: o\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(state, "csm.db"), []byte("fake-db"), 0o600); err != nil {
		t.Fatal(err)
	}

	out := filepath.Join(dir, "backup.tar.gz")
	if err := WriteBackupArchive(out, BackupSources{
		ConfigPath: cfgPath, ConfDir: confd, StateDir: state,
	}); err != nil {
		t.Fatal(err)
	}

	got := tarNames(t, out)
	for _, want := range []string{"csm.yaml", "conf.d/10.yaml", "state/csm.db"} {
		if !got[want] {
			t.Fatalf("expected %s in archive, got %v", want, got)
		}
	}
}

func TestBackupArchive_ManifestPresent(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "backup.tar.gz")
	if err := WriteBackupArchive(out, BackupSources{}); err != nil {
		t.Fatal(err)
	}
	got := tarNames(t, out)
	if !got["manifest.txt"] {
		t.Fatalf("expected manifest.txt in archive, got %v", got)
	}
}

func TestBackupArchive_IsOwnerReadableOnly(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "backup.tar.gz")
	oldUmask := syscall.Umask(0)
	defer syscall.Umask(oldUmask)

	if err := WriteBackupArchive(out, BackupSources{}); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(out)
	if err != nil {
		t.Fatal(err)
	}
	if got := st.Mode().Perm(); got != 0o600 {
		t.Fatalf("backup mode = %04o, want 0600", got)
	}
}

func TestBackupArchiveGuarded_RefusesWhenStateLockHeld(t *testing.T) {
	dir := t.TempDir()
	stateDir := filepath.Join(dir, "state")
	if mkdirErr := os.MkdirAll(stateDir, 0o700); mkdirErr != nil {
		t.Fatal(mkdirErr)
	}
	held, err := state.AcquireLock(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Release()
	out := filepath.Join(dir, "backup.tar.gz")

	err = writeBackupArchiveGuarded(out, BackupSources{StateDir: stateDir})
	if err == nil || !errors.Is(err, errBackupDaemonLive) {
		t.Fatalf("backup with state lock held error = %v, want errBackupDaemonLive", err)
	}
	if _, statErr := os.Stat(out); !os.IsNotExist(statErr) {
		t.Fatalf("backup was created despite held state lock: %v", statErr)
	}
}

func TestBackupArchive_DoesNotIncludeOutputInsideStateDir(t *testing.T) {
	dir := t.TempDir()
	state := filepath.Join(dir, "state")
	if err := os.MkdirAll(state, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(state, "csm.db"), []byte("fake-db"), 0o600); err != nil {
		t.Fatal(err)
	}

	out := filepath.Join(state, "backup.tar.gz")
	if err := WriteBackupArchive(out, BackupSources{StateDir: state}); err != nil {
		t.Fatal(err)
	}

	got := tarNames(t, out)
	if got["state/backup.tar.gz"] {
		t.Fatalf("backup archive included itself: %v", got)
	}
	if !got["state/csm.db"] {
		t.Fatalf("expected state/csm.db in archive, got %v", got)
	}
}

func TestBackupArchive_SkipsStateLockFile(t *testing.T) {
	dir := t.TempDir()
	state := filepath.Join(dir, "state")
	if err := os.MkdirAll(state, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(state, "csm.db"), []byte("fake-db"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(state, daemonStateLockFileName), []byte("12345\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	out := filepath.Join(dir, "backup.tar.gz")
	if err := WriteBackupArchive(out, BackupSources{StateDir: state}); err != nil {
		t.Fatal(err)
	}

	got := tarNames(t, out)
	if got["state/"+daemonStateLockFileName] {
		t.Fatalf("backup archive included runtime lock file: %v", got)
	}
	if !got["state/csm.db"] {
		t.Fatalf("expected state/csm.db in archive, got %v", got)
	}
}

func TestBackupArchive_SkipsSpecialFiles(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "csm-backup-special-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	stateDir := filepath.Join(dir, "state")
	if mkdirErr := os.MkdirAll(stateDir, 0o700); mkdirErr != nil {
		t.Fatal(mkdirErr)
	}
	socketPath := filepath.Join(stateDir, "worker.sock")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()

	out := filepath.Join(dir, "backup.tar.gz")
	if backupErr := WriteBackupArchive(out, BackupSources{StateDir: stateDir}); backupErr != nil {
		t.Fatal(backupErr)
	}
	if got := tarNames(t, out); got["state/worker.sock"] {
		t.Fatalf("backup archive included Unix socket: %v", got)
	}
}

func TestBackupArchive_RefusesToOverwriteConfig(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "csm.yaml")
	original := []byte("hostname: keep\n")
	if err := os.WriteFile(cfgPath, original, 0o600); err != nil {
		t.Fatal(err)
	}

	if err := WriteBackupArchive(cfgPath, BackupSources{ConfigPath: cfgPath}); err == nil {
		t.Fatal("expected error when output path is the config file")
	}
	got, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(original) {
		t.Fatalf("config was overwritten: got %q", got)
	}
}

func tarNames(t *testing.T, archivePath string) map[string]bool {
	t.Helper()
	f, err := os.Open(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gr, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if closeErr := gr.Close(); closeErr != nil {
			t.Fatal(closeErr)
		}
	}()
	tr := tar.NewReader(gr)
	names := make(map[string]bool)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		names[hdr.Name] = true
	}
	return names
}
