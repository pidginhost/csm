package checks

import (
	"context"
	"os"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/state"
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
	_ = wpInstalls(ctx, "wp_core")
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
	_ = wpInstalls(ctx, "wp_core")

	if !collectorMarked(collector, "db_objects") || !collectorMarked(collector, "wp_core") {
		t.Error("cached discovery did not credit both callers with the gap")
	}
}

func TestWPInstalls_CachedOwnerGapPreventsFindingRetirement(t *testing.T) {
	old := osFS
	fs := &mockOSGlobRoots{files: []string{"/home/alice/public_html/wp-config.php"}}
	fs.readFile = func(string) ([]byte, error) { return nil, os.ErrPermission }
	osFS = fs
	t.Cleanup(func() { osFS = old })

	st, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	st.SetLatestFindings([]alert.Finding{
		{Check: "db_unexpected_trigger", Message: "existing database finding"},
		{
			Check:    "wp_core_integrity",
			Message:  "existing core finding",
			FilePath: "/home/alice/www/wp-includes/version.php",
		},
	})

	parent, gaps := WithCoverageGaps(context.Background())
	findings, purge := runParallelWithContext(parent, &config.Config{}, st, []namedCheck{
		{
			name: "db_objects",
			fn: func(ctx context.Context, _ *config.Config, _ *state.Store) []alert.Finding {
				_ = wpInstalls(ctx, "db_objects")
				return nil
			},
		},
		{
			name: "wp_core",
			fn: func(ctx context.Context, _ *config.Config, _ *state.Store) []alert.Finding {
				_ = wpInstalls(ctx, "wp_core")
				return nil
			},
		},
	}, "test", true)
	StoreLatestScanFindingsWithGaps(st, purge, findings, gaps.Paths())

	got := st.LatestFindings()
	for _, check := range []string{"db_unexpected_trigger", "wp_core_integrity"} {
		if !containsFindingCheck(got, check) {
			t.Errorf("cached discovery gap retired %q: findings=%+v purge=%v", check, got, purge)
		}
	}
	if paths := gaps.Paths(); paths != nil {
		t.Errorf("host-wide discovery gap was narrowed to paths: %v", paths)
	}
}

func TestPluginDiscoveryCreditsBothInventoryConsumers(t *testing.T) {
	old := osFS
	fs := &mockOSGlobRoots{}
	fs.readFile = func(string) ([]byte, error) { return nil, os.ErrPermission }
	osFS = fs
	t.Cleanup(func() { osFS = old })

	ctx, collector := withIncompleteCheckCollector(context.Background())
	ctx = withWPInstallCache(ctx)
	_ = findAllWPInstalls(ctx)

	if !collectorMarked(collector, "outdated_plugins") ||
		!collectorMarked(collector, "vulnerable_plugins") {
		t.Fatal("shared plugin inventory gap was not credited to both checks")
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
