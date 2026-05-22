package checks

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/platform"
)

// writeAccessLog drops a single CLF line into path and forces its mtime
// to make freshness deterministic across the cutoff.
func writeAccessLog(t *testing.T, path string, mtime time.Time) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	line := "203.0.113.5 - - [14/Apr/2026:10:00:00 +0000] \"POST /wp-login.php HTTP/1.1\" 401 0 \"-\" \"-\"\n"
	if err := os.WriteFile(path, []byte(line), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, mtime, mtime); err != nil {
		t.Fatal(err)
	}
}

// resolveReal mirrors discoverFreshDomlogs' EvalSymlinks call so test
// assertions can compare against the same resolved paths the helper
// returns (Darwin resolves /var -> /private/var, etc.).
func resolveReal(t *testing.T, path string) string {
	t.Helper()
	real, err := filepath.EvalSymlinks(path)
	if err != nil {
		t.Fatalf("EvalSymlinks(%s): %v", path, err)
	}
	return real
}

// discoverFreshDomlogs is the single source of truth for which per-vhost
// access logs scanDomlogs and scanDomlogsStats touch each cycle. Pin
// the contract so a future change cannot quietly drift the two callers
// apart.
func TestDiscoverFreshDomlogs_RanksFreshOverStaleAndAppliesCap(t *testing.T) {
	tmp := t.TempDir()
	now := time.Now()

	veryFresh := filepath.Join(tmp, "fresh-a/access.log")
	freshish := filepath.Join(tmp, "fresh-b/access.log")
	stale := filepath.Join(tmp, "stale/access.log")
	writeAccessLog(t, veryFresh, now.Add(-1*time.Minute))
	writeAccessLog(t, freshish, now.Add(-10*time.Minute))
	writeAccessLog(t, stale, now.Add(-2*time.Hour))

	platform.ResetForTest()
	platform.SetOverrides(platform.Overrides{DomlogGlobs: []string{tmp + "/*/access.log"}})
	t.Cleanup(platform.ResetForTest)

	withMockOS(t, &mockOS{
		glob: func(string) ([]string, error) { return []string{veryFresh, freshish, stale}, nil },
		stat: os.Stat,
	})

	got := discoverFreshDomlogs(context.Background(), 0)
	if len(got) != 2 {
		t.Fatalf("want 2 (stale dropped), got %d: %v", len(got), got)
	}
	wantFresh := resolveReal(t, veryFresh)
	wantFreshish := resolveReal(t, freshish)
	if got[0] != wantFresh || got[1] != wantFreshish {
		t.Errorf("ranking wrong; got %v want [%s %s]", got, wantFresh, wantFreshish)
	}

	capped := discoverFreshDomlogs(context.Background(), 1)
	if len(capped) != 1 || capped[0] != wantFresh {
		t.Errorf("cap=1 must keep most-recent only; got %v", capped)
	}
}

// scanDomlogs and scanDomlogsStats must scan the SAME files for the
// SAME cycle. Both wrappers route through discoverFreshDomlogs; this
// test pins that contract by counting scanned files.
func TestScanDomlogsAndScanDomlogsStatsTouchSameFiles(t *testing.T) {
	tmp := t.TempDir()
	now := time.Now()

	one := filepath.Join(tmp, "one/access.log")
	two := filepath.Join(tmp, "two/access.log")
	three := filepath.Join(tmp, "three/access.log")
	writeAccessLog(t, one, now.Add(-1*time.Minute))
	writeAccessLog(t, two, now.Add(-5*time.Minute))
	writeAccessLog(t, three, now.Add(-10*time.Minute))

	platform.ResetForTest()
	platform.SetOverrides(platform.Overrides{DomlogGlobs: []string{tmp + "/*/access.log"}})
	t.Cleanup(platform.ResetForTest)

	withMockOS(t, &mockOS{
		glob: func(string) ([]string, error) { return []string{one, two, three}, nil },
		stat: os.Stat,
		open: os.Open,
	})

	mapScanned := scanDomlogs(context.Background(), nil, 0,
		map[string]int{}, map[string]int{}, map[string]int{})

	statsScanned := scanDomlogsStats(context.Background(), &config.Config{}, newDomlogStats())

	if mapScanned != statsScanned {
		t.Errorf("scanDomlogs scanned=%d but scanDomlogsStats scanned=%d -- discovery drift",
			mapScanned, statsScanned)
	}
	if mapScanned != 3 {
		t.Errorf("expected 3 fresh logs scanned, got %d", mapScanned)
	}
}

// Central logs in the well-known set are excluded from per-vhost
// discovery so CheckWPBruteForce's separate central-log pass does
// not double-count traffic.
func TestDiscoverFreshDomlogs_ExcludesCentralAccessLogs(t *testing.T) {
	tmp := t.TempDir()
	now := time.Now()

	// Use a real path that EvalSymlinks resolves to itself; we want
	// the excluded check (not the symlink dedupe) to drop it. The
	// excluded set is keyed on the resolved path, so we have to
	// arrange for one of our temp paths to compare equal to a
	// known central log key.
	vhost := filepath.Join(tmp, "vhost/access.log")
	writeAccessLog(t, vhost, now)

	platform.ResetForTest()
	platform.SetOverrides(platform.Overrides{DomlogGlobs: []string{tmp + "/*/access.log"}})
	t.Cleanup(platform.ResetForTest)

	// Inject a fake central path into the lookup map for the
	// duration of this test, then point the glob at it. The exclusion
	// is keyed on EvalSymlinks-resolved real paths.
	fakeCentral := filepath.Join(tmp, "central/access.log")
	writeAccessLog(t, fakeCentral, now)
	realCentral := resolveReal(t, fakeCentral)
	centralAccessLogs[realCentral] = true
	t.Cleanup(func() { delete(centralAccessLogs, realCentral) })

	withMockOS(t, &mockOS{
		glob: func(string) ([]string, error) { return []string{vhost, fakeCentral}, nil },
		stat: os.Stat,
	})

	got := discoverFreshDomlogs(context.Background(), 0)
	wantVhost := resolveReal(t, vhost)
	if len(got) != 1 || got[0] != wantVhost {
		t.Errorf("central log not excluded; got %v want only %s", got, wantVhost)
	}
}
