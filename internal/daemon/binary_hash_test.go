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
