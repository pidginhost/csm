package stalwartlog

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

func TestNewestFile(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"stalwart.log.2026-11-10", "stalwart.log.2026-11-11", "stalwart.log.2026-11-11.gz", "stalwart.log.2026-11-12x", "other.log"} {
		if err := os.WriteFile(filepath.Join(dir, name), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	got, err := NewestFile(dir, "stalwart.log")
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(dir, "stalwart.log.2026-11-11"); got != want {
		t.Fatalf("NewestFile = %q, want %q", got, want)
	}
}

func TestNewestFileMissing(t *testing.T) {
	_, err := NewestFile(t.TempDir(), "stalwart.log")
	if !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("empty dir: err = %v, want fs.ErrNotExist", err)
	}
	_, err = NewestFile(filepath.Join(t.TempDir(), "absent"), "stalwart.log")
	if !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("missing dir: err = %v, want fs.ErrNotExist", err)
	}
}
