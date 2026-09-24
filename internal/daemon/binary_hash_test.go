package daemon

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/pidginhost/csm/internal/integrity"
)

// The status API reports the binary hash on every poll. Reading the whole
// binary each time is wasted work; it is read again only when the file
// changes.
func TestBinaryHashReadsTheFileOnlyWhenItChanges(t *testing.T) {
	path := filepath.Join(t.TempDir(), "csm")
	if err := os.WriteFile(path, []byte("build one"), 0o700); err != nil {
		t.Fatal(err)
	}
	reads := 0
	old := hashBinary
	hashBinary = func(p string) (string, error) {
		reads++
		return integrity.HashFile(p)
	}
	t.Cleanup(func() { hashBinary = old })

	d := &Daemon{binaryPath: path}
	first := d.BinaryHash()
	if first == "" || d.BinaryHash() != first {
		t.Fatalf("hash = %q, then %q", first, d.BinaryHash())
	}
	if reads != 1 {
		t.Fatalf("two polls read the binary %d times, want 1", reads)
	}

	// An upgrade replaces the binary: the next poll hashes the new file.
	if err := os.WriteFile(path, []byte("build number two"), 0o700); err != nil {
		t.Fatal(err)
	}
	if got := d.BinaryHash(); got == first || got == "" {
		t.Fatalf("hash after replace = %q, want a new hash", got)
	}
	if reads != 2 {
		t.Fatalf("reads = %d after the binary changed, want 2", reads)
	}
}

func TestBinaryHashRecomputesAfterReplacementDuringHash(t *testing.T) {
	path := filepath.Join(t.TempDir(), "csm")
	if err := os.WriteFile(path, []byte("old binary"), 0o700); err != nil {
		t.Fatal(err)
	}
	old := hashBinary
	reads := 0
	hashBinary = func(p string) (string, error) {
		reads++
		h, err := integrity.HashFile(p)
		if err == nil && reads == 1 {
			if writeErr := os.WriteFile(p, []byte("replacement binary"), 0o700); writeErr != nil {
				t.Fatal(writeErr)
			}
		}
		return h, err
	}
	t.Cleanup(func() { hashBinary = old })
	var cache binaryHashCache
	first := cache.get(path)
	want, err := integrity.HashFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := cache.get(path); got != want || got == first || reads != 2 {
		t.Fatalf("after replacement: got %q, want %q, reads=%d", got, want, reads)
	}
	if got := cache.get(path); got != want || reads != 2 {
		t.Fatalf("stable file: got %q, want %q, reads=%d", got, want, reads)
	}
}
