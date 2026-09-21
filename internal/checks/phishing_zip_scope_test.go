package checks

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// A ZIP the kit scanner declines to open is a scope decision, not a coverage
// failure: the size bounds exist so an attacker-controlled archive cannot make
// the scan expensive. Treating that decline as an incomplete check would put
// phishing permanently in the unpurgeable set on any host that keeps a large
// backup archive under a docroot, so a stale phishing finding for a file that
// is long gone could never retire.
func TestPhishingOversizedKitZipDoesNotBlockPurge(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "phishing-kit.zip")
	// Comfortably past the scanner's upper bound, written sparsely.
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(60 * 1024 * 1024); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	ctx, collector := withIncompleteCheckCollector(context.Background())
	if zipLooksLikeKit(ctx, path) {
		t.Fatal("an oversized archive must not be reported as a kit")
	}
	if collector.contains("phishing") {
		t.Fatal("declining an out-of-scope archive marked the whole phishing check incomplete, which blocks it from ever retiring a stale finding")
	}
}

// The same holds for a path that is not a regular file: there is nothing to
// inspect, and nothing about it makes the rest of the scan incomplete.
func TestPhishingNonRegularKitZipDoesNotBlockPurge(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "kit.zip")
	if err := os.Mkdir(path, 0o755); err != nil {
		t.Fatal(err)
	}

	ctx, collector := withIncompleteCheckCollector(context.Background())
	if zipLooksLikeKit(ctx, path) {
		t.Fatal("a directory must not be reported as a kit")
	}
	if collector.contains("phishing") {
		t.Fatal("a non-regular path marked the whole phishing check incomplete")
	}
}
