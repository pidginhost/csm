package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/integrity"
)

// The daemon's helper writes the signed config it is handed, keeps the old
// file as a backup, and refuses input it does not recognise.
func TestRunConfigWrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "csm.yaml")
	if err := os.WriteFile(path, []byte("hostname: old\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	data := []byte("hostname: new\n")
	data = append(data, []byte("integrity:\n  config_hash: "+integrity.HashConfigStableBytes(data)+"\n")...)
	body, err := json.Marshal(integrity.SignedConfig{Path: path, Bytes: data, Fragments: map[string][]byte{}})
	if err != nil {
		t.Fatal(err)
	}
	var errOut bytes.Buffer
	if code := runConfigWrite(bytes.NewReader(body), &errOut); code != 0 {
		t.Fatalf("exit %d: %s", code, errOut.String())
	}
	if got, _ := os.ReadFile(path); !bytes.Equal(got, data) {
		t.Fatalf("config = %q", got)
	}
	if got, _ := os.ReadFile(path + ".bak"); string(got) != "hostname: old\n" {
		t.Fatalf("backup = %q", got)
	}

	errOut.Reset()
	other := filepath.Join(dir, "other.conf")
	bad, _ := json.Marshal(integrity.SignedConfig{Path: other, Bytes: []byte("x")})
	if code := runConfigWrite(bytes.NewReader(bad), &errOut); code == 0 || !strings.Contains(errOut.String(), "config-write") {
		t.Fatalf("exit %d, stderr %q: want a refusal", code, errOut.String())
	}
	if _, err := os.Stat(other); err == nil {
		t.Fatal("a refused request wrote a file")
	}
}

func TestRunConfigWriteRestorePreservesSidecars(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "csm.yaml")
	link := filepath.Join(t.TempDir(), "legacy.yaml")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	original := []byte("hostname: current\n")
	if err := os.WriteFile(target, original, 0600); err != nil {
		t.Fatal(err)
	}
	record, err := integrity.FragmentRecordPath(target)
	if err != nil {
		t.Fatal(err)
	}
	for _, sidecar := range []string{target + ".bak", record} {
		if writeErr := os.WriteFile(sidecar, []byte("preserve me"), 0600); writeErr != nil {
			t.Fatal(writeErr)
		}
	}
	data := []byte("hostname: restored\n")
	data = append(data, []byte("integrity:\n  config_hash: "+integrity.HashConfigStableBytes(data)+"\n  confd_hash: sha256:old\n")...)
	body, err := json.Marshal(integrity.SignedConfig{Path: link, Bytes: data})
	if err != nil {
		t.Fatal(err)
	}
	var errOut bytes.Buffer
	if code := runConfigWrite(bytes.NewReader(body), &errOut); code != 0 {
		t.Fatalf("exit %d: %s", code, errOut.String())
	}
	if got, readErr := os.ReadFile(target); readErr != nil || !bytes.Equal(got, data) {
		t.Fatal("restore did not preserve the signed bytes")
	}
	if st, statErr := os.Lstat(link); statErr != nil || st.Mode()&os.ModeSymlink == 0 {
		t.Fatal("legacy link was replaced")
	}
	for _, sidecar := range []string{target + ".bak", record} {
		if got, readErr := os.ReadFile(sidecar); readErr != nil || string(got) != "preserve me" {
			t.Fatal("restore changed a sidecar")
		}
	}
}

func TestRunConfigWriteRejectsUnsignedWithoutWrites(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "csm.yaml")
	original := []byte("hostname: original\n")
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(integrity.SignedConfig{Path: path, Bytes: []byte("hostname: unsigned\n"), Fragments: map[string][]byte{}})
	if err != nil {
		t.Fatal(err)
	}
	var errOut bytes.Buffer
	if code := runConfigWrite(bytes.NewReader(body), &errOut); code == 0 {
		t.Fatal("unsigned config accepted")
	}
	if got, readErr := os.ReadFile(path); readErr != nil || !bytes.Equal(got, original) {
		t.Fatal("rejected write changed main config")
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 {
		t.Fatal("rejected write created sidecars")
	}
}
