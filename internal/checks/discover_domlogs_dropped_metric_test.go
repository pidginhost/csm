package checks

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/platform"
)

// Discovery must report broken symlinks and stat failures through the
// dropped-domlog counter so operators can spot a shrinking scan set.
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

	beforeBroken := scrapeDomlogDropReasons(t)

	got := discoverFreshDomlogs(context.Background(), 0)
	if len(got) != 1 {
		t.Errorf("expected 1 surviving log, got %d (%v)", len(got), got)
	}

	afterBroken := scrapeDomlogDropReasons(t)
	if got := afterBroken["evalsymlinks_error"] - beforeBroken["evalsymlinks_error"]; got != 1 {
		t.Errorf("broken symlink must increment evalsymlinks_error once, got delta %g", got)
	}
	if got := afterBroken["stat_error"] - beforeBroken["stat_error"]; got != 0 {
		t.Errorf("broken symlink must not increment stat_error, got delta %g", got)
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

	before := scrapeDomlogDropReasons(t)
	if got := discoverFreshDomlogs(context.Background(), 0); len(got) != 0 {
		t.Errorf("stat failure must drop the entry, got %v", got)
	}
	after := scrapeDomlogDropReasons(t)
	if got := after["stat_error"] - before["stat_error"]; got != 1 {
		t.Errorf("stat error must increment stat_error once, got delta %g", got)
	}
	if got := after["evalsymlinks_error"] - before["evalsymlinks_error"]; got != 0 {
		t.Errorf("stat error must not increment evalsymlinks_error, got delta %g", got)
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

	before := scrapeDomlogDropReasons(t)
	_ = discoverFreshDomlogs(context.Background(), 0)
	after := scrapeDomlogDropReasons(t)
	for reason, want := range before {
		if after[reason] != want {
			t.Errorf("stale mtime must not increment %s: before=%g after=%g", reason, want, after[reason])
		}
	}
}

func scrapeDomlogDropReasons(t *testing.T) map[string]float64 {
	t.Helper()
	out := map[string]float64{
		"evalsymlinks_error": 0,
		"stat_error":         0,
	}
	for _, line := range strings.Split(scrape(t), "\n") {
		if !strings.HasPrefix(line, `csm_checks_domlog_discovery_dropped_total{reason=`) {
			continue
		}
		open := strings.Index(line, `"`)
		if open < 0 {
			continue
		}
		rest := line[open+1:]
		end := strings.Index(rest, `"`)
		if end < 0 {
			continue
		}
		reason := rest[:end]
		after := strings.TrimSpace(strings.TrimPrefix(rest[end+1:], "}"))
		if after == "" {
			continue
		}
		value, err := parseScraperFloat(after)
		if err != nil {
			continue
		}
		out[reason] = value
	}
	return out
}
