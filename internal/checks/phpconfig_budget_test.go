package checks

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// The PHP-config walk budget was shared across every document root on an
// account, so a busy first root consumed it and every later root was reported
// as "could not finish scanning" without being walked at all. Real accounts hit
// this routinely: one with several addon domains has tens of thousands of
// directories under vendor and node_modules trees, well past the shared limit.
//
// Each root now gets its own allowance, and a separate per-account ceiling
// still stops a pathological tree from occupying a scan worker.

func makeDirTree(t *testing.T, root string, dirs int) {
	t.Helper()
	if err := os.MkdirAll(root, 0755); err != nil {
		t.Fatalf("mkdir root: %v", err)
	}
	for i := 0; i < dirs; i++ {
		if err := os.MkdirAll(filepath.Join(root, "d"+string(rune('a'+i))), 0755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
	}
}

func withWalkLimits(t *testing.T, perRootDirs, perAccountDirs int) {
	t.Helper()
	origRoot, origAccount := phpIniWalkMaxDirs, phpIniWalkAccountMaxDirs
	phpIniWalkMaxDirs, phpIniWalkAccountMaxDirs = perRootDirs, perAccountDirs
	t.Cleanup(func() {
		phpIniWalkMaxDirs, phpIniWalkAccountMaxDirs = origRoot, origAccount
	})
}

func TestPHPIniWalkBudgetIsPerRoot(t *testing.T) {
	withWalkLimits(t, 6, 1000)
	base := t.TempDir()
	rootA := filepath.Join(base, "a")
	rootB := filepath.Join(base, "b")
	makeDirTree(t, rootA, 4)
	makeDirTree(t, rootB, 4)
	if err := os.WriteFile(filepath.Join(rootB, "php.ini"), []byte("disable_functions=\n"), 0644); err != nil {
		t.Fatalf("write php.ini: %v", err)
	}

	budget := &phpIniWalkBudget{}
	if _, complete := collectPHPIniFilesWithBudget(context.Background(), rootA, -1, budget); !complete {
		t.Fatal("first root should complete within its own allowance")
	}
	paths, complete := collectPHPIniFilesWithBudget(context.Background(), rootB, -1, budget)
	if !complete {
		t.Error("second root was starved by the first root's walk")
	}
	if len(paths) != 1 {
		t.Errorf("second root php.ini found = %d, want 1", len(paths))
	}
}

func TestPHPIniWalkAccountCeilingStillStops(t *testing.T) {
	withWalkLimits(t, 100, 6)
	base := t.TempDir()
	budget := &phpIniWalkBudget{}
	sawIncomplete := false
	for _, name := range []string{"a", "b", "c", "d"} {
		root := filepath.Join(base, name)
		makeDirTree(t, root, 4)
		if _, complete := collectPHPIniFilesWithBudget(context.Background(), root, -1, budget); !complete {
			sawIncomplete = true
		}
	}
	if !sawIncomplete {
		t.Error("per-account ceiling must still stop a runaway account")
	}
}
