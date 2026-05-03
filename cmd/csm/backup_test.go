package main

import (
	"archive/tar"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"testing"
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
	defer gr.Close()
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
