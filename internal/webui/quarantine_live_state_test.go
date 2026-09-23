package webui

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/integrity"
)

// The quarantine list compares every entry with the live file. Hashing both
// on each request is repeated work; a pair is hashed again only when either
// file changes.
func TestQuarantineLiveStateHashesAPairOnlyWhenItChanges(t *testing.T) {
	dir := t.TempDir()
	archive := filepath.Join(dir, "archive")
	original := filepath.Join(dir, "original.php")
	for _, p := range []string{archive, original} {
		if err := os.WriteFile(p, []byte("<?php echo 1;"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	hashes := 0
	old := hashLiveStateFile
	hashLiveStateFile = func(p string) (string, error) {
		hashes++
		return integrity.HashFile(p)
	}
	t.Cleanup(func() { hashLiveStateFile = old })

	if got := quarantineLiveState(archive, original); got != "restored_identical" {
		t.Fatalf("state = %q", got)
	}
	if got := quarantineLiveState(archive, original); got != "restored_identical" || hashes != 2 {
		t.Fatalf("second look: state %q after %d hashes, want no new hashes", got, hashes)
	}

	// Same size, different content: the change must be noticed.
	time.Sleep(10 * time.Millisecond)
	if err := os.WriteFile(original, []byte("<?php echo 2;"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := quarantineLiveState(archive, original); got != "live_differs" || hashes != 4 {
		t.Fatalf("after a change: state %q after %d hashes, want live_differs after 4", got, hashes)
	}
}
