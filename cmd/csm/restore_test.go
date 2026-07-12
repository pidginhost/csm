package main

import (
	"archive/tar"
	"compress/gzip"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/state"
)

// A live daemon holds state/csm.db open and mmap'd; bbolt's flock is
// advisory, so an O_TRUNC extraction would corrupt both the live and
// the restored state. The guarded entry point used by `csm restore`
// must refuse before touching any destination file, mirroring
// `csm store import`.
func TestRestoreArchiveGuarded_RefusesWhenDaemonLive(t *testing.T) {
	src := t.TempDir()
	dst := t.TempDir()

	for _, p := range []string{src + "/conf.d", src + "/state", dst + "/state"} {
		if err := os.MkdirAll(p, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(src+"/csm.yaml", []byte("h: from-archive\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(src+"/state/csm.db", []byte("ARCHIVE-DB"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Sentinel standing in for the daemon's open database file.
	if err := os.WriteFile(dst+"/state/csm.db", []byte("LIVE-DB"), 0o600); err != nil {
		t.Fatal(err)
	}

	archive := filepath.Join(src, "backup.tar.gz")
	if err := WriteBackupArchive(archive, BackupSources{
		ConfigPath: src + "/csm.yaml", ConfDir: src + "/conf.d", StateDir: src + "/state",
	}); err != nil {
		t.Fatal(err)
	}

	// Fake live daemon: isDaemonLive dials controlSocketPath, so a bare
	// listener is all "live" means for the refusal check.
	sock := shortSockPath(t)
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listening on %s: %v", sock, err)
	}
	defer func() { _ = l.Close() }()
	saved := controlSocketPath
	controlSocketPath = sock
	defer func() { controlSocketPath = saved }()

	err = restoreBackupArchiveGuarded(archive, BackupSources{
		ConfigPath: dst + "/csm.yaml", ConfDir: dst + "/conf.d", StateDir: dst + "/state",
	})
	if err == nil {
		t.Fatal("expected refusal while daemon is live, got nil")
	}
	if !strings.Contains(err.Error(), "daemon is running") {
		t.Fatalf("refusal error should say the daemon is running, got %v", err)
	}

	got, readErr := os.ReadFile(dst + "/state/csm.db")
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(got) != "LIVE-DB" {
		t.Fatalf("live db was touched despite refusal, got %q", got)
	}
	if _, statErr := os.Stat(dst + "/csm.yaml"); !os.IsNotExist(statErr) {
		t.Fatalf("config written despite refusal: %v", statErr)
	}
	if _, statErr := os.Stat(dst + "/conf.d"); !os.IsNotExist(statErr) {
		t.Fatalf("conf.d created despite refusal: %v", statErr)
	}
}

func TestRestoreArchiveGuarded_ProceedsWhenDaemonDown(t *testing.T) {
	src := t.TempDir()
	dst := t.TempDir()

	for _, p := range []string{src + "/conf.d", src + "/state"} {
		if err := os.MkdirAll(p, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(src+"/csm.yaml", []byte("h: from-archive\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(src+"/state/csm.db", []byte("ARCHIVE-DB"), 0o600); err != nil {
		t.Fatal(err)
	}

	archive := filepath.Join(src, "backup.tar.gz")
	if err := WriteBackupArchive(archive, BackupSources{
		ConfigPath: src + "/csm.yaml", ConfDir: src + "/conf.d", StateDir: src + "/state",
	}); err != nil {
		t.Fatal(err)
	}

	saved := controlSocketPath
	controlSocketPath = shortSockPath(t) // path exists only as a string; no listener
	defer func() { controlSocketPath = saved }()

	if err := restoreBackupArchiveGuarded(archive, BackupSources{
		ConfigPath: dst + "/csm.yaml", ConfDir: dst + "/conf.d", StateDir: dst + "/state",
	}); err != nil {
		t.Fatalf("restore with stopped daemon should proceed: %v", err)
	}

	got, err := os.ReadFile(dst + "/state/csm.db")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "ARCHIVE-DB" {
		t.Fatalf("state not restored, got %q", got)
	}
	if _, err := os.Stat(dst + "/csm.yaml"); err != nil {
		t.Fatalf("config not restored: %v", err)
	}
}

// A daemon takes the state lock before it opens bbolt or binds the
// control socket, so there is a window where the socket check reports
// "down" while the daemon is very much alive. Restoring then would
// corrupt the db it is about to open. The guard must also refuse when
// the state lock cannot be acquired.
func TestRestoreArchiveGuarded_RefusesWhenStateLockHeld(t *testing.T) {
	src := t.TempDir()
	dst := t.TempDir()

	for _, p := range []string{src + "/conf.d", src + "/state", dst + "/state"} {
		if err := os.MkdirAll(p, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(src+"/csm.yaml", []byte("h: from-archive\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(src+"/state/csm.db", []byte("ARCHIVE-DB"), 0o600); err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(src, "backup.tar.gz")
	if err := WriteBackupArchive(archive, BackupSources{
		ConfigPath: src + "/csm.yaml", ConfDir: src + "/conf.d", StateDir: src + "/state",
	}); err != nil {
		t.Fatal(err)
	}

	// Stand in for the running-but-not-yet-listening daemon by holding
	// the state lock ourselves; the second acquire inside the guard must
	// fail (flock conflicts across open file descriptions).
	held, err := state.AcquireLock(dst + "/state")
	if err != nil {
		t.Fatalf("acquiring state lock: %v", err)
	}
	defer held.Release()

	saved := controlSocketPath
	controlSocketPath = shortSockPath(t) // no listener: socket check says "down"
	defer func() { controlSocketPath = saved }()

	err = restoreBackupArchiveGuarded(archive, BackupSources{
		ConfigPath: dst + "/csm.yaml", ConfDir: dst + "/conf.d", StateDir: dst + "/state",
	})
	if err == nil {
		t.Fatal("expected refusal while the state lock is held, got nil")
	}
	if _, statErr := os.Stat(dst + "/csm.yaml"); !os.IsNotExist(statErr) {
		t.Fatalf("config written despite refusal: %v", statErr)
	}
}

// A backup captured while the daemon ran can contain the runtime lock
// file. Restoring it verbatim would plant a stale lock that blocks the
// next start, so the restore path must skip it.
func TestRestoreArchive_SkipsStateLockFile(t *testing.T) {
	src := t.TempDir()
	dst := t.TempDir()
	archive := filepath.Join(src, "backup.tar.gz")
	if err := writeArchiveEntry(archive, "state/"+daemonStateLockFileName, 4, []byte("123\n")); err != nil {
		t.Fatal(err)
	}

	if err := RestoreBackupArchive(archive, BackupSources{
		ConfigPath: dst + "/csm.yaml", ConfDir: dst + "/conf.d", StateDir: dst + "/state",
	}); err != nil {
		t.Fatal(err)
	}

	if _, statErr := os.Stat(dst + "/state/" + daemonStateLockFileName); !os.IsNotExist(statErr) {
		t.Fatal("restore planted the runtime lock file instead of skipping it")
	}
}

func TestRestoreArchive_RoundTrip(t *testing.T) {
	src := t.TempDir()
	dst := t.TempDir()

	for _, p := range []string{src + "/conf.d", src + "/state", dst + "/conf.d", dst + "/state"} {
		if err := os.MkdirAll(p, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(src+"/csm.yaml", []byte("h: original\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(src+"/conf.d/10.yaml", []byte("k: v\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(src+"/state/csm.db", []byte("DB"), 0o600); err != nil {
		t.Fatal(err)
	}

	archive := filepath.Join(src, "backup.tar.gz")
	if err := WriteBackupArchive(archive, BackupSources{
		ConfigPath: src + "/csm.yaml", ConfDir: src + "/conf.d", StateDir: src + "/state",
	}); err != nil {
		t.Fatal(err)
	}

	if err := RestoreBackupArchive(archive, BackupSources{
		ConfigPath: dst + "/csm.yaml", ConfDir: dst + "/conf.d", StateDir: dst + "/state",
	}); err != nil {
		t.Fatal(err)
	}

	got, err := os.ReadFile(dst + "/csm.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "h: original\n" {
		t.Fatalf("config not restored, got %q", got)
	}
	if _, err := os.Stat(dst + "/conf.d/10.yaml"); err != nil {
		t.Fatalf("conf.d not restored: %v", err)
	}
	if _, err := os.Stat(dst + "/state/csm.db"); err != nil {
		t.Fatalf("state not restored: %v", err)
	}
}

func TestRestoreArchive_EmptyStateRemovesStaleDataButKeepsLock(t *testing.T) {
	src := t.TempDir()
	dst := t.TempDir()
	sourceState := filepath.Join(src, "state")
	targetState := filepath.Join(dst, "state")
	if err := os.MkdirAll(sourceState, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(targetState, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(targetState, "stale.db"), []byte("stale"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(targetState, daemonStateLockFileName), []byte("lock"), 0o600); err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(src, "backup.tar.gz")
	if err := WriteBackupArchive(archive, BackupSources{StateDir: sourceState}); err != nil {
		t.Fatal(err)
	}
	if err := RestoreBackupArchive(archive, BackupSources{StateDir: targetState}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(targetState, "stale.db")); !os.IsNotExist(err) {
		t.Fatalf("stale state survived restore: %v", err)
	}
	if data, err := os.ReadFile(filepath.Join(targetState, daemonStateLockFileName)); err != nil || string(data) != "lock" {
		t.Fatalf("state lock changed during restore: data=%q err=%v", data, err)
	}
}

func TestRestoreArchive_CreatesNestedDestinationParents(t *testing.T) {
	src := t.TempDir()
	dst := t.TempDir()
	archive := filepath.Join(src, "backup.tar.gz")
	if err := writeArchiveEntry(archive, "conf.d/nested/10.yaml", 5, []byte("k: v\n")); err != nil {
		t.Fatal(err)
	}

	if err := RestoreBackupArchive(archive, BackupSources{
		ConfigPath: dst + "/csm.yaml", ConfDir: dst + "/conf.d", StateDir: dst + "/state",
	}); err != nil {
		t.Fatal(err)
	}

	got, err := os.ReadFile(filepath.Join(dst, "conf.d", "nested", "10.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "k: v\n" {
		t.Fatalf("nested config fragment not restored, got %q", got)
	}
}

func TestRestoreArchive_MissingArchiveErrors(t *testing.T) {
	dir := t.TempDir()
	if err := RestoreBackupArchive(filepath.Join(dir, "nope.tar.gz"), BackupSources{
		ConfigPath: dir + "/csm.yaml", ConfDir: dir + "/conf.d", StateDir: dir + "/state",
	}); err == nil {
		t.Fatal("expected error for missing archive")
	}
}

func TestRestoreArchive_RejectsArchiveWithoutManifest(t *testing.T) {
	archive := filepath.Join(t.TempDir(), "no-manifest.tar.gz")
	if err := writeArchiveWithoutManifest(archive, "csm.yaml", []byte("hostname: x\n")); err != nil {
		t.Fatal(err)
	}
	err := RestoreBackupArchive(archive, BackupSources{ConfigPath: filepath.Join(t.TempDir(), "csm.yaml")})
	if err == nil || !strings.Contains(err.Error(), "manifest") {
		t.Fatalf("restore error = %v, want missing manifest rejection", err)
	}
}

func TestRestoreArchive_RejectsManifestWithPrefixedSchemaKey(t *testing.T) {
	archive := filepath.Join(t.TempDir(), "bad-manifest.tar.gz")
	badManifest := []byte("backup_ts=2026-07-12T00:00:00Z\nxschema=1\n")
	if err := writeArchiveEntries(archive, []archiveTestEntry{
		{name: "csm.yaml", size: 12, body: []byte("hostname: x\n")},
		{name: "manifest.txt", size: int64(len(badManifest)), body: badManifest},
	}); err != nil {
		t.Fatal(err)
	}
	err := RestoreBackupArchive(archive, BackupSources{ConfigPath: filepath.Join(t.TempDir(), "csm.yaml")})
	if err == nil || !strings.Contains(err.Error(), "manifest") {
		t.Fatalf("restore error = %v, want invalid manifest rejection", err)
	}
}

func TestRestoreArchive_RejectsTarPathTraversal(t *testing.T) {
	// Defense-in-depth: a malicious archive shouldn't be able to write
	// outside the destination via "../" entries.
	src := t.TempDir()
	dst := t.TempDir()
	if err := os.MkdirAll(dst+"/conf.d", 0o700); err != nil {
		t.Fatal(err)
	}

	// Hand-craft an archive with a path-traversal entry.
	archive := filepath.Join(src, "evil.tar.gz")
	if err := writeMaliciousArchive(t, archive); err != nil {
		t.Fatal(err)
	}

	err := RestoreBackupArchive(archive, BackupSources{
		ConfigPath: dst + "/csm.yaml", ConfDir: dst + "/conf.d", StateDir: dst + "/state",
	})
	// Either the restore returns an error OR silently skips the malicious
	// entry -- but in BOTH cases the parent directory must NOT contain a
	// file written by the archive.
	parent := filepath.Dir(dst) + "/escaped.txt"
	if _, statErr := os.Stat(parent); statErr == nil {
		t.Fatalf("path traversal succeeded: %s exists (restore err=%v)", parent, err)
	}
	if err == nil {
		t.Fatal("expected path traversal archive to be rejected")
	}
}

func TestRestoreArchive_RejectsOversizedEntry(t *testing.T) {
	src := t.TempDir()
	dst := t.TempDir()
	archive := filepath.Join(src, "huge.tar.gz")
	if err := writeArchiveEntry(archive, "state/huge.db", maxRestoreEntrySize+1, nil); err != nil {
		t.Fatal(err)
	}

	err := RestoreBackupArchive(archive, BackupSources{
		ConfigPath: dst + "/csm.yaml", ConfDir: dst + "/conf.d", StateDir: dst + "/state",
	})
	if err == nil || !strings.Contains(err.Error(), "size") {
		t.Fatalf("expected oversized entry error, got %v", err)
	}
	if _, statErr := os.Stat(dst + "/state/huge.db"); !os.IsNotExist(statErr) {
		t.Fatalf("oversized entry created target file: %v", statErr)
	}
}

func TestRestoreArchive_InvalidLateEntryLeavesDestinationsUnchanged(t *testing.T) {
	src := t.TempDir()
	dst := t.TempDir()
	archive := filepath.Join(src, "invalid-late.tar.gz")
	if err := writeArchiveEntries(archive, []archiveTestEntry{
		{name: "csm.yaml", size: 18, body: []byte("hostname: changed\n")},
		{name: "conf.d/../escaped.yaml", size: 0},
	}); err != nil {
		t.Fatal(err)
	}
	original := []byte("hostname: original\n")
	configPath := filepath.Join(dst, "csm.yaml")
	if err := os.WriteFile(configPath, original, 0o600); err != nil {
		t.Fatal(err)
	}

	err := RestoreBackupArchive(archive, BackupSources{
		ConfigPath: configPath,
		ConfDir:    filepath.Join(dst, "conf.d"),
		StateDir:   filepath.Join(dst, "state"),
	})
	if err == nil {
		t.Fatal("expected invalid archive to fail")
	}
	got, readErr := os.ReadFile(configPath)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(got) != string(original) {
		t.Fatalf("config changed before archive validation completed: got %q", got)
	}
}

func TestRestoreArchive_CommitFailureRollsBackEarlierTargets(t *testing.T) {
	src := t.TempDir()
	dst := t.TempDir()
	archive := filepath.Join(src, "backup.tar.gz")
	if err := writeArchiveEntries(archive, []archiveTestEntry{
		{name: "csm.yaml", size: 18, body: []byte("hostname: changed\n")},
		{name: "conf.d/10.yaml", size: 14, body: []byte("value: changed")},
	}); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(dst, "csm.yaml")
	confDir := filepath.Join(dst, "conf.d")
	if err := os.MkdirAll(confDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, []byte("hostname: original\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(confDir, "10.yaml"), []byte("value: original"), 0o600); err != nil {
		t.Fatal(err)
	}

	originalRename := renameRestorePath
	renameRestorePath = func(oldPath, newPath string) error {
		if newPath == confDir && strings.Contains(filepath.Base(oldPath), ".csm-restore-new-") {
			return errors.New("injected install failure")
		}
		return os.Rename(oldPath, newPath)
	}
	defer func() { renameRestorePath = originalRename }()

	err := RestoreBackupArchive(archive, BackupSources{
		ConfigPath: configPath,
		ConfDir:    confDir,
		StateDir:   filepath.Join(dst, "state"),
	})
	if err == nil || !strings.Contains(err.Error(), "injected install failure") {
		t.Fatalf("restore error = %v, want injected install failure", err)
	}
	config, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(config) != "hostname: original\n" {
		t.Fatalf("config was not rolled back: %q", config)
	}
	fragment, err := os.ReadFile(filepath.Join(confDir, "10.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if string(fragment) != "value: original" {
		t.Fatalf("conf.d was not rolled back: %q", fragment)
	}
}

func TestRestoreArchive_ReportsRollbackFailure(t *testing.T) {
	src := t.TempDir()
	dst := t.TempDir()
	archive := filepath.Join(src, "backup.tar.gz")
	if err := writeArchiveEntries(archive, []archiveTestEntry{
		{name: "csm.yaml", size: 18, body: []byte("hostname: changed\n")},
		{name: "conf.d/10.yaml", size: 14, body: []byte("value: changed")},
	}); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(dst, "csm.yaml")
	confDir := filepath.Join(dst, "conf.d")
	if err := os.MkdirAll(confDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, []byte("hostname: original\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(confDir, "10.yaml"), []byte("value: original"), 0o600); err != nil {
		t.Fatal(err)
	}

	originalRename := renameRestorePath
	renameRestorePath = func(oldPath, newPath string) error {
		if newPath == confDir && strings.Contains(filepath.Base(oldPath), ".csm-restore-new-") {
			return errors.New("injected install failure")
		}
		if newPath == configPath && strings.Contains(filepath.Base(oldPath), ".csm-restore-old-") {
			return errors.New("injected rollback failure")
		}
		return os.Rename(oldPath, newPath)
	}
	defer func() { renameRestorePath = originalRename }()

	err := RestoreBackupArchive(archive, BackupSources{ConfigPath: configPath, ConfDir: confDir})
	if err == nil || !strings.Contains(err.Error(), "injected install failure") || !strings.Contains(err.Error(), "injected rollback failure") {
		t.Fatalf("restore error = %v, want both install and rollback failures", err)
	}
}

type archiveTestEntry struct {
	name string
	size int64
	body []byte
}

func writeArchiveEntries(archivePath string, entries []archiveTestEntry) error {
	f, err := os.Create(archivePath)
	if err != nil {
		return err
	}
	defer f.Close()
	gw := gzip.NewWriter(f)
	tw := tar.NewWriter(gw)
	for _, entry := range entries {
		if err := tw.WriteHeader(&tar.Header{Name: entry.name, Mode: 0o600, Size: entry.size}); err != nil {
			return err
		}
		if len(entry.body) > 0 {
			if _, err := tw.Write(entry.body); err != nil {
				return err
			}
		}
	}
	hasManifest := false
	for _, entry := range entries {
		if entry.name == "manifest.txt" {
			hasManifest = true
			break
		}
	}
	if !hasManifest {
		manifest := []byte("backup_ts=2026-07-12T00:00:00Z\nschema=1\n")
		if err := tw.WriteHeader(&tar.Header{Name: "manifest.txt", Mode: 0o600, Size: int64(len(manifest))}); err != nil {
			return err
		}
		if _, err := tw.Write(manifest); err != nil {
			return err
		}
	}
	if err := tw.Close(); err != nil {
		return err
	}
	return gw.Close()
}

func writeMaliciousArchive(t *testing.T, archivePath string) error {
	t.Helper()
	return writeArchiveEntry(archivePath, "conf.d/../escaped.txt", 3, []byte("bad"))
}

func writeArchiveEntry(archivePath, name string, size int64, body []byte) error {
	f, err := os.Create(archivePath)
	if err != nil {
		return err
	}
	defer f.Close()

	gw := gzip.NewWriter(f)
	tw := tar.NewWriter(gw)
	writersClosed := false
	defer func() {
		if !writersClosed {
			_ = tw.Close()
			_ = gw.Close()
		}
	}()

	if writeErr := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: size}); writeErr != nil {
		return writeErr
	}
	if len(body) > 0 {
		if _, err = tw.Write(body); err != nil {
			return err
		}
	}
	if int64(len(body)) < size {
		return nil
	}
	manifest := []byte("backup_ts=2026-07-12T00:00:00Z\nschema=1\n")
	if err = tw.WriteHeader(&tar.Header{Name: "manifest.txt", Mode: 0o600, Size: int64(len(manifest))}); err != nil {
		return err
	}
	if _, err = tw.Write(manifest); err != nil {
		return err
	}
	if err = tw.Close(); err != nil {
		return err
	}
	if err = gw.Close(); err != nil {
		return err
	}
	writersClosed = true
	return nil
}

func writeArchiveWithoutManifest(archivePath, name string, body []byte) error {
	f, err := os.Create(archivePath)
	if err != nil {
		return err
	}
	gw := gzip.NewWriter(f)
	tw := tar.NewWriter(gw)
	if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: int64(len(body))}); err != nil {
		_ = f.Close()
		return err
	}
	if _, err := tw.Write(body); err != nil {
		_ = f.Close()
		return err
	}
	if err := tw.Close(); err != nil {
		_ = f.Close()
		return err
	}
	if err := gw.Close(); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}
