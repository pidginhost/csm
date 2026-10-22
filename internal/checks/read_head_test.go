package checks

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestReadRegularFileHeadBoundsProductionReads(t *testing.T) {
	dir := t.TempDir()
	big := filepath.Join(dir, "big")
	if err := os.WriteFile(big, bytes.Repeat([]byte("a"), 1<<20), 0o600); err != nil {
		t.Fatal(err)
	}
	data, truncated, err := readRegularFileHead(big, 1000)
	if err != nil || len(data) != 1000 || !truncated {
		t.Fatalf("big: len=%d truncated=%v err=%v", len(data), truncated, err)
	}
	small := filepath.Join(dir, "small")
	if err := os.WriteFile(small, []byte("hi"), 0o600); err != nil {
		t.Fatal(err)
	}
	if data, truncated, err := readRegularFileHead(small, 1000); err != nil || string(data) != "hi" || truncated {
		t.Fatalf("small: %q %v %v", data, truncated, err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(big, link); err != nil {
		t.Fatal(err)
	}
	if _, _, err := readRegularFileHead(link, 1000); err == nil {
		t.Fatal("followed a final symlink")
	}
}
