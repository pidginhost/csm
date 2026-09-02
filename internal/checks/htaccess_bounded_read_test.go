package checks

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// Every scheduled .htaccess reader loaded the whole file into memory with no
// bound, so a tenant could park a multi-gigabyte .htaccess and turn the deep
// scan into an OOM crash loop. The shared reader stops at the realtime
// ceiling and tells the caller the file was too large to judge.
func TestReadHtaccessBoundedRefusesOversizedFiles(t *testing.T) {
	dir := t.TempDir()
	small := filepath.Join(dir, "small")
	if err := os.WriteFile(small, []byte("RewriteEngine On\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	data, ok, err := readHtaccessBounded(small)
	if err != nil || !ok || !bytes.Equal(data, []byte("RewriteEngine On\n")) {
		t.Fatalf("small file: data=%q ok=%v err=%v", data, ok, err)
	}

	huge := filepath.Join(dir, "huge")
	f, err := os.Create(huge)
	if err != nil {
		t.Fatal(err)
	}
	if truncErr := f.Truncate(htaccessMaxFileBytes + 1); truncErr != nil {
		t.Fatal(truncErr)
	}
	_ = f.Close()
	data, ok, err = readHtaccessBounded(huge)
	if err != nil {
		t.Fatalf("oversized file returned an error instead of a refusal: %v", err)
	}
	if ok || data != nil {
		t.Fatalf("oversized file was read: ok=%v len=%d", ok, len(data))
	}
}
