package main

import (
	"archive/tar"
	"compress/gzip"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/state"
	csmstore "github.com/pidginhost/csm/internal/store"
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
	createBackupTestDB(t, state)

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
	createBackupTestDB(t, state)

	out := filepath.Join(state, "backup.tar.gz")
	if err := WriteBackupArchive(out, BackupSources{StateDir: state}); err != nil {
		t.Fatal(err)
	}

	got := tarNames(t, out)
	if got["state/backup.tar.gz"] {
		t.Fatalf("backup archive included itself: %v", got)
	}
	for name := range got {
		if strings.Contains(name, ".csm-backup-db-") {
			t.Fatalf("backup archive included its temporary database snapshot as %q", name)
		}
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
	createBackupTestDB(t, state)
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

func TestBackupArchiveSkipsPendingFirewallRollback(t *testing.T) {
	dir := t.TempDir()
	stateDir := filepath.Join(dir, "state")
	for _, rel := range daemonStateTransientPaths {
		path := filepath.Join(stateDir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("pending"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	stagedExport := filepath.Join(stateDir, "exports", "export-orphan", "staged.csmbak")
	if err := os.MkdirAll(filepath.Dir(stagedExport), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(stagedExport, []byte("partial"), 0o600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "backup.tar.gz")
	if err := WriteBackupArchive(out, BackupSources{StateDir: stateDir}); err != nil {
		t.Fatal(err)
	}
	names := tarNames(t, out)
	for _, rel := range daemonStateTransientPaths {
		if names["state/"+rel] || archiveHasPrefix(names, "state/"+rel+"/") {
			t.Fatalf("backup included transient rollback state %q", rel)
		}
	}
	if archiveHasPrefix(names, "state/exports/") {
		t.Fatal("backup included transient export staging")
	}
}

func TestBackupArchiveDisarmsPendingFirewallConfigRollback(t *testing.T) {
	dir := t.TempDir()
	stateDir := filepath.Join(dir, "state")
	db, openErr := csmstore.Open(stateDir)
	if openErr != nil {
		t.Fatal(openErr)
	}
	if err := db.SaveFirewallRollback(csmstore.FirewallRollback{PrevYAML: []byte("old"), ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "backup.tar.gz")
	if err := WriteBackupArchive(out, BackupSources{StateDir: stateDir}); err != nil {
		t.Fatal(err)
	}
	restoredDir := filepath.Join(dir, "snapshot")
	if err := os.Mkdir(restoredDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(restoredDir, "csm.db"), tarEntryBytes(t, out, "state/csm.db"), 0o600); err != nil {
		t.Fatal(err)
	}
	snapshot, openErr := csmstore.Open(restoredDir)
	if openErr != nil {
		t.Fatal(openErr)
	}
	t.Cleanup(func() { _ = snapshot.Close() })
	if _, ok := snapshot.GetFirewallRollback(); ok {
		t.Fatal("backup retained a pending firewall configuration rollback")
	}
}

func archiveHasPrefix(names map[string]bool, prefix string) bool {
	for name := range names {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
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
	fifoPath := filepath.Join(stateDir, "worker.fifo")
	if err := syscall.Mkfifo(fifoPath, 0o600); err != nil {
		t.Fatal(err)
	}

	out := filepath.Join(dir, "backup.tar.gz")
	if backupErr := WriteBackupArchive(out, BackupSources{StateDir: stateDir}); backupErr != nil {
		t.Fatal(backupErr)
	}
	if got := tarNames(t, out); got["state/worker.fifo"] {
		t.Fatalf("backup archive included named pipe: %v", got)
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

func tarEntryBytes(t *testing.T, archivePath, want string) []byte {
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
	defer func() { _ = gr.Close() }()
	tr := tar.NewReader(gr)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			t.Fatalf("archive entry %q not found", want)
		}
		if err != nil {
			t.Fatal(err)
		}
		if hdr.Name == want {
			data, err := io.ReadAll(tr)
			if err != nil {
				t.Fatal(err)
			}
			return data
		}
	}
}

func createBackupTestDB(t *testing.T, stateDir string) {
	t.Helper()
	db, err := csmstore.Open(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
}
