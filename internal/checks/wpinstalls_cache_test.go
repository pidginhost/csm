package checks

import (
	"context"
	"os"
	"testing"
)

// countingGlobFS counts how many globs a discovery costs.
type countingGlobFS struct {
	mockOSGlobRoots
	globs int
}

func (m *countingGlobFS) Glob(pattern string) ([]string, error) {
	m.globs++
	return m.mockOSGlobRoots.Glob(pattern)
}

// Nine WordPress consumers run per cycle. Each one walking every account home
// is the cost this cache exists to remove.
func TestWPInstalls_CachePerCycleWalksOnce(t *testing.T) {
	old := osFS
	fake := &countingGlobFS{mockOSGlobRoots: mockOSGlobRoots{files: []string{
		"/home/alice/public_html/wp-config.php",
	}}}
	osFS = fake
	t.Cleanup(func() { osFS = old })

	ctx := withWPInstallCache(context.Background())
	_ = wpInstalls(ctx, "db_objects")
	after := fake.globs
	_ = wpInstalls(ctx, "wp_core_integrity")
	if fake.globs != after {
		t.Errorf("second consumer re-walked: %d globs after first, %d after second", after, fake.globs)
	}
}

// A cache hit must still credit the second caller's coverage gaps, or a check
// silently inherits another check's completeness and purges findings it should
// have preserved.
func TestWPInstalls_CacheReplaysGapsPerCaller(t *testing.T) {
	old := osFS
	fs := &mockOSGlobRoots{files: []string{"/home/alice/public_html/wp-config.php"}}
	fs.readFile = func(string) ([]byte, error) { return nil, os.ErrPermission }
	osFS = fs
	t.Cleanup(func() { osFS = old })

	ctx, collector := withIncompleteCheckCollector(context.Background())
	ctx = withWPInstallCache(ctx)
	_ = wpInstalls(ctx, "db_objects")
	_ = wpInstalls(ctx, "wp_core_integrity")

	if !collectorMarked(collector, "db_objects") || !collectorMarked(collector, "wp_core_integrity") {
		t.Error("cached discovery did not credit both callers with the gap")
	}
}

// Fix and re-check paths build their own context. They must re-discover: they
// act on the tree they just changed.
func TestWPInstalls_NoCacheWithoutCycleContext(t *testing.T) {
	old := osFS
	fake := &countingGlobFS{mockOSGlobRoots: mockOSGlobRoots{files: []string{
		"/home/alice/public_html/wp-config.php",
	}}}
	osFS = fake
	t.Cleanup(func() { osFS = old })

	_ = wpInstalls(context.Background(), "db_objects")
	after := fake.globs
	_ = wpInstalls(context.Background(), "db_objects")
	if fake.globs == after {
		t.Error("discovery was cached without a cycle context")
	}
}

// One account's cached discovery must never answer for another account.
func TestWPInstalls_CacheKeyedByAccount(t *testing.T) {
	old := osFS
	osFS = &mockOSGlobRoots{files: []string{
		"/home/alice/public_html/wp-config.php",
		"/home/bob/public_html/wp-config.php",
	}}
	t.Cleanup(func() { osFS = old })

	ctx := withWPInstallCache(context.Background())
	if got := wpInstallsForAccount(ctx, "db_clean", "alice"); len(got) != 1 || got[0].Account != "alice" {
		t.Fatalf("alice discovery = %v", wpInstallPaths(got))
	}
	got := wpInstallsForAccount(ctx, "db_clean", "bob")
	if len(got) != 1 || got[0].Account != "bob" {
		t.Errorf("bob discovery = %v, want bob only", wpInstallPaths(got))
	}
}
