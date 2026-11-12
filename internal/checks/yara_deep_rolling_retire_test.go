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
	"github.com/pidginhost/csm/internal/jstaint"
	"github.com/pidginhost/csm/internal/phptaint"
	"github.com/pidginhost/csm/internal/state"
	"github.com/pidginhost/csm/internal/store"
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

func TestRollingYARARunKeepsNestedRootFindingAtBudget(t *testing.T) {
	useRollingStore(t)
	root := t.TempDir()
	target := t.TempDir()
	writeYARADeepFile(t, target, "payload.dat", "mal payload")
	linked := filepath.Join(root, "a-linked")
	if err := os.Symlink(target, linked); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(linked, "payload.dat")
	writeYARADeepFile(t, root, "z-stop.dat", "clean stop")
	st := openRollingRetireState(t)
	cfg := &config.Config{AccountRoots: []string{root, linked}}
	backend := &recordingYARABackend{}
	yara.SetActive(backend)
	t.Cleanup(func() { yara.SetActive(nil) })
	runDeepTierCycle(t, st, cfg)
	if !latestScheduledPaths(st)[path] {
		t.Fatal("initial scan did not detect the payload through its configured root")
	}

	base := time.Now().Add(time.Hour)
	clock := base
	backend.scanned = nil
	backend.onScan = func() { clock = clock.Add(2 * yaraDeepDeadlineMargin) }
	useYARADeepClock(t, &clock)
	ctx, cancel := context.WithDeadline(context.Background(), base.Add(yaraDeepDeadlineMargin+time.Minute))
	defer cancel()
	ctx, coverage := withCoveragePathCollector(ctx)
	ctx, incomplete := withIncompleteCheckCollector(ctx)
	findings := CheckYARADeep(ctx, cfg, st)
	if !incomplete.contains("yara_deep") || len(backend.scanned) != 1 {
		t.Fatalf("wanted a partial scan of one file, got %v", backend.scanned)
	}
	StoreLatestScanFindingsWithCoverage(st, nil, findings, &state.ScanCoverage{
		CompletedScopes: map[string]map[string]bool{"yara_match_scheduled": coverage.completedScopes("yara_deep")},
	})
	if !latestScheduledPaths(st)[path] {
		t.Fatal("partial scan retired a payload under a root it never visited")
	}
}

func TestRollingDeepWalkOrdersOverlappingRoots(t *testing.T) {
	useRollingStore(t)
	root := t.TempDir()
	real := filepath.Join(root, "a-real")
	writeYARADeepFile(t, real, "one.dat", "clean real")
	target := t.TempDir()
	writeYARADeepFile(t, target, "two.dat", "clean linked")
	linked := filepath.Join(root, "b-linked")
	if err := os.Symlink(target, linked); err != nil {
		t.Fatal(err)
	}
	writeYARADeepFile(t, root, "z-last.dat", "clean last")
	cfg := &config.Config{AccountRoots: []string{linked, real, root}}
	wantScanned(t, runYARADeepWindow(t, context.Background(), cfg, false), "clean real", "clean linked", "clean last")
}

func TestRollingDeepCoverageWindowBoundaries(t *testing.T) {
	paths := []string{"/r/aa", "/r/ab.zz", "/r/ab/first", "/r/ab/last", "/r/z", "/r-other/file"}
	var prior []alert.Finding
	for _, path := range paths {
		prior = append(prior, scheduledYARAFinding(yara.Match{RuleName: "test"}, path, nil, "sha"))
	}
	for _, tc := range []struct {
		name, resume, last string
		stopped            bool
		want               []string
	}{
		{name: "dot sibling before directory", resume: "/r/ab.zz", last: "/r/ab/first", stopped: true, want: paths[2:3]},
		{name: "stop at dot sibling", last: "/r/ab.zz", stopped: true, want: paths[:2]},
		{name: "resume past subtree", resume: "/r/ab/", want: paths[4:5]},
		{name: "stop after subtree", last: "/r/ab/", stopped: true, want: paths[:4]},
		{name: "leading consumer not reached", resume: "/r/z", last: "/r/z", stopped: true},
		{name: "no progress", stopped: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := &yaraDeepWalk{roots: []string{"/r"}, stoppedEarly: tc.stopped}
			c := &deepScanConsumer{resume: tc.resume, lastScanned: tc.last}
			got := w.examinedScopes(c, prior, "yara_match_scheduled", func(string) bool { return false })
			if len(got) != len(tc.want) {
				t.Fatalf("completed scopes = %v, want paths %v", got, tc.want)
			}
			for _, path := range tc.want {
				if !got[deepFileCoverageScope(path)] {
					t.Errorf("missing completed scope for %s", path)
				}
			}
		})
	}
}

func TestRollingDeepConsumersRetireTheirOwnWindows(t *testing.T) {
	for _, stop := range []bool{false, true} {
		name := "finish"
		if stop {
			name = "stop"
		}
		t.Run(name, func(t *testing.T) {
			db := useRollingStore(t)
			enablePHPTaintConsumer(t)
			root := t.TempDir()
			paths := []string{
				writeYARADeepFile(t, root, "a.dat", "clean first"),
				writeYARADeepFile(t, root, "ab.zz", "clean dot sibling"),
				writeYARADeepFile(t, root, "ab/child", "clean child"),
				writeYARADeepFile(t, root, "z.dat", "clean last"),
			}
			var prior []alert.Finding
			for _, path := range paths {
				prior = append(prior,
					scheduledYARAFinding(yara.Match{RuleName: "test"}, path, nil, "sha"),
					jsTaintDeepFinding(path, "sha", jstaint.Report{}),
					phpTaintDeepFinding(path, "sha", phptaint.Report{}))
			}
			st := openRollingRetireState(t)
			st.SetLatestFindings(prior)
			for owner, resume := range map[string]string{
				"yara_deep":             deepSubtreePrefix(filepath.Join(root, "ab")),
				logicalOwnerJSTaintDeep: paths[0], logicalOwnerPHPTaintDeep: paths[3],
			} {
				if err := db.PutScanCursor(store.ScanCursorRecord{Check: owner, LastPath: resume}); err != nil {
					t.Fatal(err)
				}
			}
			yara.SetActive(&recordingYARABackend{})
			t.Cleanup(func() { yara.SetActive(nil) })
			base := time.Now().Add(time.Hour)
			clock := base
			useYARADeepClock(t, &clock)
			previousAnalyze := jsTaintAnalyze
			jsTaintAnalyze = func(ctx context.Context, data []byte) jstaint.Report {
				if stop && string(data) == "clean child" {
					clock = clock.Add(2 * yaraDeepDeadlineMargin)
				}
				return previousAnalyze(ctx, data)
			}
			t.Cleanup(func() { jsTaintAnalyze = previousAnalyze })
			ctx, cancel := context.WithDeadline(context.Background(), base.Add(yaraDeepDeadlineMargin+time.Minute))
			defer cancel()
			ctx, coverage := withCoveragePathCollector(ctx)
			ctx, _ = withIncompleteCheckCollector(ctx)
			findings := CheckYARADeep(ctx, &config.Config{AccountRoots: []string{root}}, st)
			StoreLatestScanFindingsWithCoverage(st, nil, findings, &state.ScanCoverage{CompletedScopes: map[string]map[string]bool{
				"yara_match_scheduled":  coverage.completedScopes("yara_deep"),
				"js_keylogger_dataflow": coverage.completedScopes(logicalOwnerJSTaintDeep),
				"php_remote_taint":      coverage.completedScopes(logicalOwnerPHPTaintDeep),
			}})
			got := make(map[string]bool)
			for _, f := range st.LatestFindings() {
				got[f.Key()] = true
			}
			for _, f := range prior {
				want := true
				switch f.Check {
				case "yara_match_scheduled":
					want = stop || f.FilePath != paths[3]
				case "js_keylogger_dataflow":
					want = f.FilePath == paths[0] || (stop && f.FilePath == paths[3])
				}
				if got[f.Key()] != want {
					t.Errorf("%s at %s retained = %v, want %v", f.Check, f.FilePath, got[f.Key()], want)
				}
			}
		})
	}
}

func TestRollingDeepCoveragePreservesGapsAndPriorState(t *testing.T) {
	for _, owner := range []string{"yara_deep", logicalOwnerJSTaintDeep, logicalOwnerPHPTaintDeep} {
		for _, gap := range []string{"known", "unknown", "truncated"} {
			t.Run(owner+"/"+gap, func(t *testing.T) {
				st := openRollingRetireState(t)
				root := t.TempDir()
				makeFinding := func(name string) alert.Finding {
					path := filepath.Join(root, name)
					switch owner {
					case logicalOwnerJSTaintDeep:
						return jsTaintDeepFinding(path, "sha", jstaint.Report{})
					case logicalOwnerPHPTaintDeep:
						return phpTaintDeepFinding(path, "sha", phptaint.Report{})
					default:
						return scheduledYARAFinding(yara.Match{RuleName: "test"}, path, nil, "sha")
					}
				}
				clean, gapped := makeFinding("b-clean"), makeFinding("c-gap")
				legacy, demoted := makeFinding("d-legacy"), makeFinding("e-demoted")
				legacy.CoverageScope = ""
				demoted.Severity = alert.Critical
				st.SetLatestFindings([]alert.Finding{clean, gapped, legacy, demoted})
				if !st.DemoteLatestFinding(demoted, alert.Warning) {
					t.Fatal("could not demote prior finding")
				}
				deep := namedCheck{name: "yara_deep", fn: func(ctx context.Context, _ *config.Config, _ *state.Store) []alert.Finding {
					w := &yaraDeepWalk{
						ctx: ctx, roots: []string{root},
						yaraConsumer: &deepScanConsumer{}, jsConsumer: &deepScanConsumer{}, phpConsumer: &deepScanConsumer{},
						yaraGaps: newYARAGapCollector(), jsGaps: newJSTaintGapCollector(), phpGaps: newPHPTaintGapCollector(),
					}
					c := &deepScanConsumer{dispatch: true, resume: filepath.Join(root, "a-resume")}
					markCheckIncomplete(ctx, "yara_deep")
					markCheckIncomplete(ctx, logicalOwnerJSTaintDeep)
					markCheckIncomplete(ctx, logicalOwnerPHPTaintDeep)
					switch owner {
					case "yara_deep":
						w.yaraConsumer = c
						w.yaraGaps.record(gapped.FilePath, "read_error")
						w.yaraGaps.pathsTruncated = gap == "truncated"
						if gap == "unknown" {
							w.yaraGaps.recordUnknownRange("unreadable directory")
						}
					case logicalOwnerJSTaintDeep:
						w.jsConsumer = c
						w.jsGaps.record(gapped.FilePath, "read_error")
						w.jsGaps.pathsTruncated = gap == "truncated"
						if gap == "unknown" {
							w.jsGaps.recordUnknownRange("unreadable directory")
						}
					case logicalOwnerPHPTaintDeep:
						w.phpConsumer = c
						w.phpGaps.record(gapped.FilePath, "read_error")
						w.phpGaps.pathsTruncated = gap == "truncated"
						if gap == "unknown" {
							w.phpGaps.recordUnknownRange("unreadable directory")
						}
					}
					w.reportCoverage(st)
					return w.findings
				}}
				ctx, coverage := WithCoverageGaps(context.Background())
				findings, purge := runParallelWithContext(ctx, &config.Config{}, st, []namedCheck{deep}, "deep", true)
				if len(coverage.Snapshot().PreservePaths) != 0 {
					t.Fatal("partial run published path preservation")
				}
				for _, f := range findings {
					if f.ScanCarryForward {
						t.Fatal("partial run carried prior state forward")
					}
				}
				StoreLatestScanFindingsWithCoverage(st, purge, findings, coverage.Snapshot())
				got := make(map[string]alert.Finding)
				for _, f := range st.LatestFindings() {
					if f.Check == clean.Check {
						got[f.Key()] = f
					}
				}
				want := []alert.Finding{gapped, legacy, demoted}
				if gap != "known" {
					want = append(want, clean)
				}
				if len(got) != len(want) {
					t.Fatalf("retained %d rows, want %d: %+v", len(got), len(want), got)
				}
				for _, f := range want {
					if _, ok := got[f.Key()]; !ok {
						t.Errorf("lost prior finding at %s", f.FilePath)
					}
				}
				if f := got[demoted.Key()]; f.Severity != alert.Warning || f.DemotedFrom != alert.Critical {
					t.Errorf("demotion changed: %+v", f)
				}
			})
		}
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
