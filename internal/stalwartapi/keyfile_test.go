package stalwartapi

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadKeyFileRefusesLooseFiles(t *testing.T) {
	t.Cleanup(SetKeyFileOwnerForTest(uint32(os.Getuid())))
	dir := t.TempDir()
	write := func(name, content string, mode os.FileMode) string {
		t.Helper()
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, mode); err != nil {
			t.Fatal(err)
		}
		return p
	}
	good := write("good", "  test-key-1\n", 0o600)
	link := filepath.Join(dir, "link")
	if err := os.Symlink(good, link); err != nil {
		t.Fatal(err)
	}
	sub := filepath.Join(dir, "sub")
	if err := os.Mkdir(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	cases := map[string]string{
		"group and other bits": write("loose", "test-key-1\n", 0o644),
		"group bits only":      write("group", "test-key-1\n", 0o640),
		"symlink":              link,
		"directory":            sub,
		"empty":                write("empty", "", 0o600),
		"white space only":     write("blank", " \n\t\n", 0o600),
		"300 bytes":            write("big", "test-key-1"+strings.Repeat("k", 290), 0o600),
	}
	for name, p := range cases {
		key, err := ReadKeyFile(p)
		if err == nil || key != "" {
			t.Errorf("%s: key %q, err %v; want a refusal", name, key, err)
			continue
		}
		if !strings.Contains(err.Error(), p) {
			t.Errorf("%s: error %q does not name the path", name, err)
		}
		if strings.Contains(err.Error(), "test-key-1") {
			t.Errorf("%s: error %q carries the file content", name, err)
		}
	}

	key, err := ReadKeyFile(good)
	if err != nil || key != "test-key-1" {
		t.Fatalf("0600 key file: key %q, err %v", key, err)
	}
	full := strings.Repeat("k", 256)
	if key, err := ReadKeyFile(write("full", full, 0o600)); err != nil || key != full {
		t.Fatalf("256-byte key: len %d, err %v", len(key), err)
	}

	// The same file owned by anyone but the required owner is refused.
	t.Cleanup(SetKeyFileOwnerForTest(uint32(os.Getuid()) + 1))
	if _, err := ReadKeyFile(good); err == nil || !strings.Contains(err.Error(), good) {
		t.Fatalf("file of another owner: err %v; want a refusal naming the path", err)
	}
}

func TestReadKeyFileMissing(t *testing.T) {
	p := filepath.Join(t.TempDir(), "absent")
	_, err := ReadKeyFile(p)
	if !errors.Is(err, ErrNoKeyFile) {
		t.Fatalf("err = %v, want ErrNoKeyFile", err)
	}
	if !strings.Contains(err.Error(), p) {
		t.Fatalf("error %q does not name the path", err)
	}
}

func TestWriteKeyFileIsPrivateAndAtomic(t *testing.T) {
	t.Cleanup(SetKeyFileOwnerForTest(uint32(os.Getuid())))
	dir := t.TempDir()
	p := filepath.Join(dir, "stalwart-api.key")
	check := func(want string) {
		t.Helper()
		info, err := os.Lstat(p)
		if err != nil {
			t.Fatal(err)
		}
		if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
			t.Fatalf("mode = %v, want a regular 0600 file", info.Mode())
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		if len(entries) != 1 {
			t.Fatalf("directory holds %d entries, want only the key file", len(entries))
		}
		if got, err := ReadKeyFile(p); err != nil || got != want {
			t.Fatalf("read back %q, err %v; want %q", got, err, want)
		}
	}

	if err := WriteKeyFile(p, "test-key-1"); err != nil {
		t.Fatal(err)
	}
	check("test-key-1")
	if err := WriteKeyFile(p, "test-key-2"); err != nil {
		t.Fatal(err)
	}
	check("test-key-2")

	// A readable file already in place is replaced, not rewritten in place.
	if err := os.Chmod(p, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := WriteKeyFile(p, "test-key-3"); err != nil {
		t.Fatal(err)
	}
	check("test-key-3")
}
