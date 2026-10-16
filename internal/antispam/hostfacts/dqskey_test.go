package hostfacts

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestReadDQSKey(t *testing.T) {
	d := t.TempDir()
	p := filepath.Join(d, "key")
	if err := os.WriteFile(p, []byte("abcdefghijklmnopqrstu23456\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	k := ReadDQSKey(p)
	if k.Err != nil || k.Missing || k.Key.Reveal() != "abcdefghijklmnopqrstu23456" || k.Mode.Perm() != 0o600 || k.UID != os.Getuid() {
		t.Fatalf("facts = %+v", k)
	}
	if k := ReadDQSKey(filepath.Join(d, "absent")); !k.Missing {
		t.Fatalf("absent = %+v", k)
	}
	link := filepath.Join(d, "link")
	if err := os.Symlink(p, link); err != nil {
		t.Fatal(err)
	}
	if k := ReadDQSKey(link); k.Err == nil {
		t.Fatal("followed a symlink")
	}
	fifo := filepath.Join(d, "fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	if k := ReadDQSKey(fifo); k.Err == nil {
		t.Fatal("accepted a FIFO")
	}
	big := filepath.Join(d, "big")
	if err := os.WriteFile(big, []byte(strings.Repeat("a", 200)), 0o600); err != nil {
		t.Fatal(err)
	}
	if k := ReadDQSKey(big); k.Err == nil || k.Key != "" {
		t.Fatalf("oversized = %+v", k)
	}
}
