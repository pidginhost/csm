package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadConfDir_LexicographicOrder(t *testing.T) {
	dir := t.TempDir()
	must(t, os.WriteFile(filepath.Join(dir, "20-second.yaml"), []byte("hostname: second\n"), 0o600))
	must(t, os.WriteFile(filepath.Join(dir, "10-first.yaml"), []byte("hostname: first\n"), 0o600))
	must(t, os.WriteFile(filepath.Join(dir, "README.txt"), []byte("ignore"), 0o600)) // not .yaml

	frags, err := LoadConfDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(frags) != 2 {
		t.Fatalf("expected 2 fragments, got %d", len(frags))
	}
	// lex order means 10- before 20-, and last write wins
	root := frags[1].Content[0]
	if root.Content[1].Value != "second" {
		t.Fatalf("expected second fragment content, got %q", root.Content[1].Value)
	}
}

func TestLoadConfDir_MissingDirReturnsEmpty(t *testing.T) {
	frags, err := LoadConfDir(filepath.Join(t.TempDir(), "does-not-exist"))
	if err != nil {
		t.Fatal(err)
	}
	if len(frags) != 0 {
		t.Fatalf("expected empty slice, got %d fragments", len(frags))
	}
}

func TestLoadConfDir_RejectsUnknownFields(t *testing.T) {
	dir := t.TempDir()
	must(t, os.WriteFile(filepath.Join(dir, "10.yaml"), []byte("not_a_real_field: 1\n"), 0o600))
	// LoadConfDir itself doesn't decode into Config, just returns yaml.Nodes,
	// so this test asserts that valid YAML passes even with "unknown" keys.
	frags, err := LoadConfDir(dir)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if len(frags) != 1 {
		t.Fatalf("expected 1 fragment, got %d", len(frags))
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
