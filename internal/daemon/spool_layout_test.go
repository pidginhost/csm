package daemon

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// Exim's split_spool_directory (the cPanel default) hashes each message into
// a single-character subdirectory of input/, so the -D file is a grandchild
// of the spool root. A watcher that marks only the root with
// FAN_EVENT_ON_CHILD never sees it.
func TestSpoolMarkTargetsCoversSplitSpoolHashDirs(t *testing.T) {
	root := t.TempDir()
	for _, d := range []string{"A", "b", "7", "lock", "AB"} {
		if err := os.Mkdir(filepath.Join(root, d), 0o750); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "1abc-D"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	got := spoolMarkTargets(root)
	want := []string{root, filepath.Join(root, "7"), filepath.Join(root, "A"), filepath.Join(root, "b")}
	if !slices.Equal(got, want) {
		t.Fatalf("spoolMarkTargets = %v, want %v", got, want)
	}

	if got := spoolMarkTargets(filepath.Join(root, "missing")); got != nil {
		t.Fatalf("missing root produced targets %v", got)
	}
}
