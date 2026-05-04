package main

import (
	"archive/tar"
	"compress/gzip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

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

func TestRestoreArchive_MissingArchiveErrors(t *testing.T) {
	dir := t.TempDir()
	if err := RestoreBackupArchive(filepath.Join(dir, "nope.tar.gz"), BackupSources{
		ConfigPath: dir + "/csm.yaml", ConfDir: dir + "/conf.d", StateDir: dir + "/state",
	}); err == nil {
		t.Fatal("expected error for missing archive")
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
	if err = tw.Close(); err != nil {
		return err
	}
	if err = gw.Close(); err != nil {
		return err
	}
	writersClosed = true
	return nil
}
