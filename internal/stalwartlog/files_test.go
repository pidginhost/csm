package stalwartlog

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"time"
)

var testNow = time.Date(2026, 11, 12, 23, 0, 0, 0, time.UTC)

func TestNewestFile(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"stalwart.log.2026-11-10", "stalwart.log.2026-11-11", "stalwart.log.2026-11-11.gz", "stalwart.log.2026-11-12x", "other.log"} {
		if err := os.WriteFile(filepath.Join(dir, name), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	got, err := NewestFile(dir, "stalwart.log", testNow)
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(dir, "stalwart.log.2026-11-11"); got != want {
		t.Fatalf("NewestFile = %q, want %q", got, want)
	}
}

func TestNewestFileMissing(t *testing.T) {
	_, err := NewestFile(t.TempDir(), "stalwart.log", testNow)
	if !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("empty dir: err = %v, want fs.ErrNotExist", err)
	}
	_, err = NewestFile(filepath.Join(t.TempDir(), "absent"), "stalwart.log", testNow)
	if !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("missing dir: err = %v, want fs.ErrNotExist", err)
	}
}

// A file dated past tomorrow cannot be Stalwart's current log; picking it
// would pin the forward-only reader on a file nobody writes.
func TestNewestFileIgnoresFutureDates(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"stalwart.log.2026-11-12", "stalwart.log.2026-11-13", "stalwart.log.2026-11-14", "stalwart.log.2099-01-01"} {
		if err := os.WriteFile(filepath.Join(dir, name), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	got, err := NewestFile(dir, "stalwart.log", testNow)
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(dir, "stalwart.log.2026-11-13"); got != want {
		t.Fatalf("NewestFile = %q, want %q (tomorrow is allowed, later dates are not)", got, want)
	}

	only := t.TempDir()
	if err := os.WriteFile(filepath.Join(only, "stalwart.log.2099-01-01"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewestFile(only, "stalwart.log", testNow); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("only a future file: err = %v, want fs.ErrNotExist", err)
	}
}
