package checks

import (
	"slices"
	"testing"
)

func TestSetAccountHomeRootsForTestRestores(t *testing.T) {
	withAccountHomeRoots(t, "/srv/original")

	restore := SetAccountHomeRootsForTest([]string{"/srv/a", "/srv/b"})
	if got := AccountHomePatterns(); !slices.Equal(got, []string{"/srv/a/*", "/srv/b/*"}) {
		restore()
		t.Fatalf("patterns while set = %v", got)
	}
	restore()
	if got := AccountHomePatterns(); !slices.Equal(got, []string{"/srv/original/*"}) {
		t.Fatalf("patterns after restore = %v", got)
	}
}

func TestSetQuarantineDirForTestRestores(t *testing.T) {
	orig := quarantineDir
	dir := t.TempDir()

	restore := SetQuarantineDirForTest(dir)
	if quarantineDir != dir {
		restore()
		t.Fatalf("quarantineDir while set = %q, want %q", quarantineDir, dir)
	}
	restore()
	if quarantineDir != orig {
		t.Fatalf("quarantineDir after restore = %q, want %q", quarantineDir, orig)
	}
}
