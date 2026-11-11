package checks

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/state"
	"github.com/pidginhost/csm/internal/yara"
)

// runDeepTierCycle runs the deep YARA check the way the daemon does and
// stores the result with the runner's coverage snapshot.
func runDeepTierCycle(t *testing.T, st *state.Store, cfg *config.Config) {
	t.Helper()
	ctx, gaps := WithCoverageGaps(context.Background())
	findings, purge := runParallelWithContext(ctx, cfg, st, []namedCheck{{name: "yara_deep", fn: CheckYARADeep}}, "deep", true)
	StoreLatestScanFindingsWithCoverage(st, purge, findings, gaps.Snapshot())
}

func latestScheduledPaths(st *state.Store) map[string]bool {
	paths := make(map[string]bool)
	for _, f := range st.LatestFindings() {
		if f.Check == "yara_match_scheduled" {
			paths[f.FilePath] = true
		}
	}
	return paths
}

// A rolling deep scan spreads one pass over many runs, and every run that
// resumes from the cursor or stops at its budget is partial. A file such a
// run examined and found clean must stop being reported; one it never
// reached must keep its finding.
func TestRollingYARARunRetiresExaminedCleanFiles(t *testing.T) {
	db := useRollingStore(t)
	root := t.TempDir()
	first := writeYARADeepFile(t, root, "a/one.dat", "mal one")
	second := writeYARADeepFile(t, root, "z/two.dat", "mal two")
	yara.SetActive(&recordingYARABackend{})
	t.Cleanup(func() { yara.SetActive(nil) })
	st := openRollingRetireState(t)
	cfg := &config.Config{AccountRoots: []string{root}}

	runDeepTierCycle(t, st, cfg)
	if got := latestScheduledPaths(st); !got[first] || !got[second] {
		t.Fatalf("first pass latest = %v, want both files", got)
	}

	if err := os.WriteFile(first, []byte("clean one"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(second, []byte("clean two"), 0o600); err != nil {
		t.Fatal(err)
	}
	putYARADeepCursor(t, db, first, st.LatestScanTime().UTC())

	runDeepTierCycle(t, st, cfg)

	got := latestScheduledPaths(st)
	if got[second] {
		t.Errorf("examined clean file still reported: latest = %v", got)
	}
	if !got[first] {
		t.Errorf("file the resumed run never reached lost its finding: latest = %v", got)
	}
	for _, f := range st.LatestFindings() {
		if f.Check == "yara_match_scheduled" && f.FilePath == first && f.Severity != alert.Critical {
			t.Errorf("unreached finding changed: %+v", f)
		}
	}
}

// A run that stops at its budget examined only the files up to where it
// stopped; files past that point keep their findings.
func TestRollingYARARunStoppedAtBudgetRetiresOnlyItsWindow(t *testing.T) {
	useRollingStore(t)
	root := t.TempDir()
	first := writeYARADeepFile(t, root, "a/one.dat", "mal one")
	second := writeYARADeepFile(t, root, "z/two.dat", "mal two")
	st := openRollingRetireState(t)
	cfg := &config.Config{AccountRoots: []string{root}}
	backend := &recordingYARABackend{}
	yara.SetActive(backend)
	t.Cleanup(func() { yara.SetActive(nil) })
	runDeepTierCycle(t, st, cfg)

	writeYARADeepFile(t, root, "a/one.dat", "clean one")
	writeYARADeepFile(t, root, "z/two.dat", "clean two")
	base := time.Now().Add(time.Hour)
	clock := base
	backend.onScan = func() { clock = clock.Add(2 * yaraDeepDeadlineMargin) }
	useYARADeepClock(t, &clock)
	ctx, cancel := context.WithDeadline(context.Background(), base.Add(yaraDeepDeadlineMargin+time.Minute))
	defer cancel()
	ctx, coverage := withCoveragePathCollector(ctx)
	ctx, incomplete := withIncompleteCheckCollector(ctx)

	findings := CheckYARADeep(ctx, cfg, st)
	if !incomplete.contains("yara_deep") {
		t.Fatal("a run stopped at its budget must stay partial")
	}
	StoreLatestScanFindingsWithCoverage(st, nil, findings, &state.ScanCoverage{
		CompletedScopes: map[string]map[string]bool{"yara_match_scheduled": coverage.completedScopes("yara_deep")},
	})

	got := latestScheduledPaths(st)
	if got[first] {
		t.Errorf("file examined before the budget ran out still reported: latest = %v", got)
	}
	if !got[second] {
		t.Errorf("file past the stop point lost its finding: latest = %v", got)
	}
}

// A file the window passed but could not inspect is a coverage gap, not a
// clean result, so its finding stays.
func TestRollingYARARunKeepsGapPathInWindow(t *testing.T) {
	db := useRollingStore(t)
	root := t.TempDir()
	first := writeYARADeepFile(t, root, "a/one.dat", "mal one")
	gapped := writeYARADeepFile(t, root, "m/two.dat", "mal two")
	clean := writeYARADeepFile(t, root, "z/three.dat", "mal three")
	yara.SetActive(&recordingYARABackend{})
	t.Cleanup(func() { yara.SetActive(nil) })
	st := openRollingRetireState(t)
	cfg := &config.Config{AccountRoots: []string{root}}
	cfg.Thresholds.FullScanMaxFileMB = 1
	runDeepTierCycle(t, st, cfg)

	writeYARADeepFile(t, root, "m/two.dat", "mal "+strings.Repeat("x", 1<<20))
	writeYARADeepFile(t, root, "z/three.dat", "clean three")
	putYARADeepCursor(t, db, first, time.Now().UTC())
	runDeepTierCycle(t, st, cfg)

	got := latestScheduledPaths(st)
	if !got[gapped] {
		t.Errorf("oversize file in the window lost its finding: latest = %v", got)
	}
	if got[clean] {
		t.Errorf("examined clean file still reported: latest = %v", got)
	}
}

// An unknown-range loss means the window cannot say which files it missed,
// so it retires nothing.
func TestRollingYARAUnknownRangeRetiresNothing(t *testing.T) {
	for _, tc := range []struct {
		name    string
		unknown bool
	}{{name: "clean window"}, {name: "unknown range", unknown: true}} {
		t.Run(tc.name, func(t *testing.T) {
			st := openRollingRetireState(t)
			path := filepath.Join(string(filepath.Separator)+"r", "z", "file.dat")
			st.SetLatestFindings([]alert.Finding{scheduledYARAFinding(yara.Match{RuleName: "test_rule"}, path, []byte("mal"), "sha")})
			ctx, coverage := withCoveragePathCollector(context.Background())
			ctx, _ = withIncompleteCheckCollector(ctx)
			w := &yaraDeepWalk{
				ctx:          ctx,
				roots:        []string{filepath.Dir(filepath.Dir(path))},
				yaraConsumer: &deepScanConsumer{name: "yara_deep", dispatch: true, resume: filepath.Join(filepath.Dir(filepath.Dir(path)), "a")},
				jsConsumer:   &deepScanConsumer{},
				phpConsumer:  &deepScanConsumer{},
				yaraGaps:     newYARAGapCollector(),
			}
			if tc.unknown {
				w.yaraGaps.recordUnknownRange("reading /r/m: permission denied")
			}

			w.reportCoverage(st)

			if got := coverage.completedScopes("yara_deep")[deepFileCoverageScope(path)]; got == tc.unknown {
				t.Fatalf("scope completed = %v, want %v", got, !tc.unknown)
			}
		})
	}
}

// The PHP and JS taint owners run inside the deep YARA check; the scopes
// their windows examined must reach their own finding names.
func TestRunnerMapsHostedOwnerScopesToTheirFindings(t *testing.T) {
	for owner, check := range map[string]string{
		logicalOwnerPHPTaintDeep: "php_remote_taint",
		logicalOwnerJSTaintDeep:  "js_keylogger_dataflow",
	} {
		t.Run(owner, func(t *testing.T) {
			scope := deepFileCoverageScope("/r/z/file")
			deep := namedCheck{name: "yara_deep", fn: func(ctx context.Context, _ *config.Config, _ *state.Store) []alert.Finding {
				markCheckIncomplete(ctx, "yara_deep")
				markCheckIncomplete(ctx, owner)
				recordCompletedCoverageScopes(ctx, owner, map[string]bool{scope: true})
				return nil
			}}
			ctx, gaps := WithCoverageGaps(context.Background())
			runParallelWithContext(ctx, &config.Config{}, nil, []namedCheck{deep}, "deep", true)

			if !gaps.Snapshot().CompletedScopes[check][scope] {
				t.Fatalf("completed scopes = %v, want %s under %s", gaps.Snapshot().CompletedScopes, scope, check)
			}
		})
	}
}

func openRollingRetireState(t *testing.T) *state.Store {
	t.Helper()
	st, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}
