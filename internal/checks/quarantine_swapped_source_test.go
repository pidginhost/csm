package checks

import (
	"os"
	"path/filepath"
	"testing"
)

// After the detected content has been captured into quarantine, an attacker
// who swaps a different file into the source path before the unlink used to
// get a silent "quarantined" result: the replacement stayed live under the
// original name while the finding was reported as remediated. The swap is a
// failure to report, with the captured copy kept as evidence.
func TestRemoveQuarantinedSourceRefusesSwappedSource(t *testing.T) {
	tmp := t.TempDir()
	src := filepath.Join(tmp, "drop.php")
	if err := os.WriteFile(src, []byte("<?php /* detected */"), 0o644); err != nil {
		t.Fatal(err)
	}
	original, err := os.Lstat(src)
	if err != nil {
		t.Fatal(err)
	}
	qPath := filepath.Join(tmp, "q", "drop.php")
	if err := os.MkdirAll(filepath.Dir(qPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(qPath, []byte("<?php /* detected */"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Rename a fresh inode over the source: a different identity, as an
	// attacker racing the unlink would produce.
	replacement := filepath.Join(tmp, "replacement.php")
	if err := os.WriteFile(replacement, []byte("<?php /* swapped in */"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(replacement, src); err != nil {
		t.Fatal(err)
	}

	if err := removeQuarantinedSource(src, qPath, original); err == nil {
		t.Fatal("a swapped source was reported as quarantined")
	}
	if got, err := os.ReadFile(src); err != nil || string(got) != "<?php /* swapped in */" {
		t.Fatalf("replacement at the source path was touched: %q, %v", got, err)
	}
	if _, err := os.Stat(qPath); err != nil {
		t.Fatalf("captured copy was discarded: %v", err)
	}
}
