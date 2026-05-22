package checks

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/platform"
)

// Discovery must report broken symlinks and stat failures through
// csm_checks_domlog_discovery_dropped_total so operators can spot a
// silently-shrinking scan set. The roadmap calls this out as the same
// hidden-input bug class the lex-order fix closed.
func TestDiscoverFreshDomlogs_SilentDropsHaveTelemetry(t *testing.T) {
	tmp := t.TempDir()
	// One real fresh log so the scrape has a baseline working scan.
	good := filepath.Join(tmp, "good/access.log")
	writeAccessLog(t, good, time.Now())

	// Broken symlink: EvalSymlinks fails. Must increment evalsymlinks_error.
	broken := filepath.Join(tmp, "broken/access.log")
	if err := os.MkdirAll(filepath.Dir(broken), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(tmp, "does-not-exist"), broken); err != nil {
		t.Fatal(err)
	}

	platform.ResetForTest()
	platform.SetOverrides(platform.Overrides{DomlogGlobs: []string{tmp + "/*/access.log"}})
	t.Cleanup(platform.ResetForTest)

	withMockOS(t, &mockOS{
		glob: func(string) ([]string, error) { return []string{good, broken}, nil },
		stat: os.Stat,
	})

	beforeBroken := scrapeSum(t, "csm_checks_domlog_discovery_dropped_total")

	got := discoverFreshDomlogs(context.Background(), 0)
	if len(got) != 1 {
		t.Errorf("expected 1 surviving log, got %d (%v)", len(got), got)
	}

	afterBroken := scrapeSum(t, "csm_checks_domlog_discovery_dropped_total")
	if afterBroken-beforeBroken < 1 {
		t.Errorf("broken symlink must increment dropped counter: before=%g after=%g", beforeBroken, afterBroken)
	}
}

// Stat-error path: EvalSymlinks succeeds (the real file exists) but the
// injected mockOS Stat returns an error, so the discovery helper drops
// the entry. Pin that the stat_error label increments.
func TestDiscoverFreshDomlogs_StatErrorsCounted(t *testing.T) {
	tmp := t.TempDir()
	target := filepath.Join(tmp, "exists/access.log")
	writeAccessLog(t, target, time.Now())

	platform.ResetForTest()
	platform.SetOverrides(platform.Overrides{DomlogGlobs: []string{tmp + "/*/access.log"}})
	t.Cleanup(platform.ResetForTest)

	withMockOS(t, &mockOS{
		glob: func(string) ([]string, error) { return []string{target}, nil },
		stat: func(string) (os.FileInfo, error) { return nil, os.ErrPermission },
	})

	before := scrapeSum(t, "csm_checks_domlog_discovery_dropped_total")
	if got := discoverFreshDomlogs(context.Background(), 0); len(got) != 0 {
		t.Errorf("stat failure must drop the entry, got %v", got)
	}
	after := scrapeSum(t, "csm_checks_domlog_discovery_dropped_total")
	if after-before < 1 {
		t.Errorf("stat error must increment dropped counter: before=%g after=%g", before, after)
	}
}

// A stale log is intentional filtering, not a hidden drop. The counter
// must NOT advance for stale-mtime cases.
func TestDiscoverFreshDomlogs_StaleDropsNotCounted(t *testing.T) {
	tmp := t.TempDir()
	stale := filepath.Join(tmp, "stale/access.log")
	writeAccessLog(t, stale, time.Now().Add(-2*time.Hour))

	platform.ResetForTest()
	platform.SetOverrides(platform.Overrides{DomlogGlobs: []string{tmp + "/*/access.log"}})
	t.Cleanup(platform.ResetForTest)

	withMockOS(t, &mockOS{
		glob: func(string) ([]string, error) { return []string{stale}, nil },
		stat: os.Stat,
	})

	before := scrapeSum(t, "csm_checks_domlog_discovery_dropped_total")
	_ = discoverFreshDomlogs(context.Background(), 0)
	after := scrapeSum(t, "csm_checks_domlog_discovery_dropped_total")
	if after != before {
		t.Errorf("stale mtime must not be counted as a silent drop: before=%g after=%g", before, after)
	}
}
