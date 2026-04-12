package checks

import (
	"os"
	"path/filepath"
	"testing"
)

// --- expandPathGlobs --------------------------------------------------

func TestExpandPathGlobsLiteral(t *testing.T) {
	got := expandPathGlobs([]string{"/etc/apache2/conf.d"})
	if len(got) != 1 || got[0] != "/etc/apache2/conf.d" {
		t.Errorf("got %v", got)
	}
}

func TestExpandPathGlobsWithGlob(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "a.conf"), []byte("x"), 0600)
	_ = os.WriteFile(filepath.Join(dir, "b.conf"), []byte("y"), 0600)
	_ = os.WriteFile(filepath.Join(dir, "c.txt"), []byte("z"), 0600)

	got := expandPathGlobs([]string{filepath.Join(dir, "*.conf")})
	if len(got) != 2 {
		t.Errorf("got %d paths, want 2: %v", len(got), got)
	}
}

func TestExpandPathGlobsDeduplication(t *testing.T) {
	got := expandPathGlobs([]string{"/a", "/b", "/a"})
	if len(got) != 2 {
		t.Errorf("duplicates should be removed, got %v", got)
	}
}

func TestExpandPathGlobsNoMatch(t *testing.T) {
	got := expandPathGlobs([]string{"/nonexistent/path/*.conf"})
	// No match falls back to the literal pattern
	if len(got) != 1 {
		t.Errorf("no match should keep literal, got %v", got)
	}
}
