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
	body, err := json.Marshal(integrity.SignedConfig{Path: path, Bytes: []byte("hostname: new\n"), Fragments: map[string][]byte{}})
	if err != nil {
		t.Fatal(err)
	}
	var errOut bytes.Buffer
	if code := runConfigWrite(bytes.NewReader(body), &errOut); code != 0 {
		t.Fatalf("exit %d: %s", code, errOut.String())
	}
	if got, _ := os.ReadFile(path); string(got) != "hostname: new\n" {
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
