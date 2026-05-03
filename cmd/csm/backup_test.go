package main

import (
	"archive/tar"
	"compress/gzip"
	"os"
	"path/filepath"
	"strings"
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

	got := listTar(t, out)
	for _, want := range []string{"csm.yaml", "conf.d/10.yaml", "state/csm.db"} {
		found := false
		for _, n := range got {
			if strings.HasSuffix(n, want) {
				found = true
				break
			}
		}
		if !found {
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
	got := listTar(t, out)
	hasManifest := false
	for _, n := range got {
		if strings.HasSuffix(n, "manifest.txt") {
			hasManifest = true
			break
		}
	}
	if !hasManifest {
		t.Fatalf("expected manifest.txt in archive, got %v", got)
	}
}

func listTar(t *testing.T, path string) []string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gr, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(gr)
	var names []string
	for {
		hdr, err := tr.Next()
		if err != nil {
			break
		}
		names = append(names, hdr.Name)
	}
	return names
}
