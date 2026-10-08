package checks

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/state"
)

func errorLogTestStore(t *testing.T) *state.Store {
	t.Helper()
	st, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

func TestErrorLogBloatReadFailuresPreserveBaseline(t *testing.T) {
	for _, failure := range []string{"directory", "entry", "skipped directory", "root metadata", "root glob"} {
		t.Run(failure, func(t *testing.T) {
			fx := newErrorLogFixture(t)
			st := errorLogTestStore(t)
			dir := filepath.Join(fx.main, "nested")
			if failure == "skipped directory" {
				dir = filepath.Join(fx.main, "wp-admin")
			}
			path := filepath.Join(dir, "error_log")
			writeSizedFile(t, path, 2*testMiB)
			now := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
			withErrorLogClock(t, &now)
			CheckErrorLogBloat(context.Background(), fx.cfg, st)
			before, _ := st.GetRaw(errorLogSizesKey)
			broken := true
			mock := osFS.(*mockOS)
			mock.stat = func(name string) (os.FileInfo, error) {
				if broken && name == fx.main && failure == "root metadata" {
					return nil, fs.ErrPermission
				}
				return os.Stat(name)
			}
			mock.readDir = func(name string) ([]os.DirEntry, error) {
				if broken && name == fx.home && failure == "root glob" {
					return nil, fs.ErrPermission
				}
				if broken && name == dir && failure == "directory" {
					return nil, fs.ErrPermission
				}
				entries, err := os.ReadDir(name)
				if broken && name == dir && failure == "entry" {
					for i := range entries {
						entries[i] = unreadableScanEntry{entries[i]}
					}
				}
				return entries, err
			}
			mock.lstat = func(name string) (os.FileInfo, error) {
				if broken && name == path && failure == "skipped directory" {
					return nil, fs.ErrPermission
				}
				return os.Lstat(name)
			}
			now = now.Add(2 * time.Hour)
			ctx, incomplete := withIncompleteCheckCollector(context.Background())
			CheckErrorLogBloat(ctx, fx.cfg, st)
			if !incomplete.contains("perf_error_logs") {
				t.Error("failed filesystem read was treated as complete")
			}
			if after, _ := st.GetRaw(errorLogSizesKey); after != before {
				t.Errorf("failed read discarded the baseline: before=%s after=%s", before, after)
			}
			broken = false
			now = now.Add(10 * time.Hour)
			writeSizedFile(t, path, 12*testMiB)
			if got := errorLogFindingFor(t, CheckErrorLogBloat(context.Background(), fx.cfg, st), path).Details; got != "Size: 12M, growing 20M/day" {
				t.Errorf("recovered growth = %q", got)
			}
		})
	}
}

func TestErrorLogBloatFailedNestedRootKeepsBaseline(t *testing.T) {
	fx := newErrorLogFixture(t)
	st := errorLogTestStore(t)
	nested := filepath.Join(fx.main, "blog")
	fx.mapDocroot(t, "alice", "blog.example.com", nested)
	path := filepath.Join(nested, "error_log")
	writeSizedFile(t, path, 2*testMiB)
	CheckErrorLogBloat(context.Background(), fx.cfg, st)
	before, _ := st.GetRaw(errorLogSizesKey)
	osFS.(*mockOS).readDir = func(name string) ([]os.DirEntry, error) {
		if name == nested {
			return nil, fs.ErrPermission
		}
		return os.ReadDir(name)
	}
	ctx, incomplete := withIncompleteCheckCollector(context.Background())
	CheckErrorLogBloat(ctx, fx.cfg, st)
	if after, _ := st.GetRaw(errorLogSizesKey); after != before || !incomplete.contains("perf_error_logs") {
		t.Fatalf("completed ancestor discarded a failed nested root: %s", after)
	}
}

func TestErrorLogBloatMissingMapKeepsUnreachedNestedBaseline(t *testing.T) {
	for _, subdir := range []string{"wp-content/site", "a/b/c/d"} {
		t.Run(subdir, func(t *testing.T) {
			fx := newErrorLogFixture(t)
			st := errorLogTestStore(t)
			nested := filepath.Join(fx.main, subdir)
			fx.mapDocroot(t, "alice", "blog.example.com", nested)
			path := filepath.Join(nested, "error_log")
			writeSizedFile(t, path, 2*testMiB)
			CheckErrorLogBloat(context.Background(), fx.cfg, st)
			before, _ := st.GetRaw(errorLogSizesKey)
			fx.mapErr = fs.ErrPermission
			ctx, coverage := withCoveragePathCollector(context.Background())
			CheckErrorLogBloat(ctx, fx.cfg, st)
			if after, _ := st.GetRaw(errorLogSizesKey); after != before {
				t.Fatalf("ancestor's limited walk discarded unvisited baseline: %s", after)
			}
			if coverage.completedScopes("perf_error_logs")[errorLogCoverageScope(path)] {
				t.Fatal("unvisited nested log was marked resolved")
			}
		})
	}
}

func TestErrorLogBloatCancellationStopsDirectoryProbes(t *testing.T) {
	fx := newErrorLogFixture(t)
	for _, dir := range []string{"cache", "vendor", "wp-admin"} {
		writeSizedFile(t, filepath.Join(fx.main, dir, "error_log"), 2*testMiB)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	probes := 0
	osFS.(*mockOS).lstat = func(path string) (os.FileInfo, error) {
		probes++
		cancel()
		return os.Lstat(path)
	}
	var scan errorLogScan
	if complete := scanErrorLogs(ctx, fx.main, testMiB, 3, nil, &scan); complete || probes != 1 {
		t.Fatalf("cancelled walk complete=%v, performed %d probes, want one", complete, probes)
	}
}

func TestErrorLogBloatPartialRunRetiresObservedBaselines(t *testing.T) {
	for _, removed := range []bool{false, true} {
		t.Run(map[bool]string{false: "small", true: "removed"}[removed], func(t *testing.T) {
			fx := newErrorLogFixture(t)
			st := errorLogTestStore(t)
			path := filepath.Join(fx.main, "error_log")
			writeSizedFile(t, path, 2*testMiB)
			CheckErrorLogBloat(context.Background(), fx.cfg, st)
			if removed {
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
			} else {
				writeSizedFile(t, path, testMiB/2)
			}
			fx.mapErr = fs.ErrPermission
			CheckErrorLogBloat(context.Background(), fx.cfg, st)
			if sizes := loadErrorLogSizes(st); len(sizes) != 0 {
				t.Fatalf("known resolved log retained a baseline: %+v", sizes)
			}
		})
	}
}

func TestErrorLogBloatPartialRunReplacesSeverityTier(t *testing.T) {
	fx := newErrorLogFixture(t)
	st := errorLogTestStore(t)
	path := filepath.Join(fx.main, "error_log")
	for _, size := range []int64{2 * testMiB, 5 * testMiB, 3 * testMiB, testMiB / 2} {
		writeSizedFile(t, path, size)
		ctx, incomplete := withIncompleteCheckCollector(context.Background())
		ctx, coverage := withCoveragePathCollector(ctx)
		findings := CheckErrorLogBloat(ctx, fx.cfg, st)
		var purge []string
		if !incomplete.contains("perf_error_logs") {
			purge = []string{"perf_error_logs"}
		}
		st.PurgeAndMergeFindingsDerivedWithCoverage(purge, findings, &state.ScanCoverage{
			CompletedScopes: map[string]map[string]bool{"perf_error_logs": coverage.completedScopes("perf_error_logs")},
		}, nil, nil)
		latest := st.LatestFindings()
		if len(latest) != len(findings) || (len(latest) == 1 && latest[0].Key() != findings[0].Key()) {
			t.Fatalf("size %d: latest=%+v, want only %+v", size, latest, findings)
		}
		fx.mapErr = fs.ErrPermission
	}
}

func TestErrorLogBloatRotationRestartsBaseline(t *testing.T) {
	fx := newErrorLogFixture(t)
	st := errorLogTestStore(t)
	path := filepath.Join(fx.main, "error_log")
	now := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	withErrorLogClock(t, &now)
	writeSizedFile(t, path, 2*testMiB)
	CheckErrorLogBloat(context.Background(), fx.cfg, st)
	if err := os.Rename(path, path+".1"); err != nil {
		t.Fatal(err)
	}
	writeSizedFile(t, path, 6*testMiB)
	now = now.Add(12 * time.Hour)
	if got := errorLogFindingFor(t, CheckErrorLogBloat(context.Background(), fx.cfg, st), path).Details; got != "Size: 6M" {
		t.Fatalf("rotated file compared with its predecessor: %q", got)
	}
	now = now.Add(12 * time.Hour)
	writeSizedFile(t, path, 8*testMiB)
	if got := errorLogFindingFor(t, CheckErrorLogBloat(context.Background(), fx.cfg, st), path).Details; got != "Size: 8M, growing 4M/day" {
		t.Fatalf("replacement file growth = %q", got)
	}
}

func TestErrorLogBloatShrinkComparedWithLatestObservation(t *testing.T) {
	fx := newErrorLogFixture(t)
	st := errorLogTestStore(t)
	path := filepath.Join(fx.main, "error_log")
	now := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	withErrorLogClock(t, &now)
	for _, size := range []int64{2, 12, 6} {
		writeSizedFile(t, path, size*testMiB)
		CheckErrorLogBloat(context.Background(), fx.cfg, st)
		now = now.Add(10 * time.Minute)
	}
	now = now.Add(12*time.Hour - 10*time.Minute)
	writeSizedFile(t, path, 8*testMiB)
	if got := errorLogFindingFor(t, CheckErrorLogBloat(context.Background(), fx.cfg, st), path).Details; got != "Size: 8M, growing 4M/day" {
		t.Fatalf("shrink during rate window did not restart baseline: %q", got)
	}
}

func TestErrorLogBloatCancellationDoesNotCommitBaselines(t *testing.T) {
	fx := newErrorLogFixture(t)
	st := errorLogTestStore(t)
	path := filepath.Join(fx.main, "error_log")
	writeSizedFile(t, path, 2*testMiB)
	CheckErrorLogBloat(context.Background(), fx.cfg, st)
	before, _ := st.GetRaw(errorLogSizesKey)
	writeSizedFile(t, path, 6*testMiB)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ctx, incomplete := withIncompleteCheckCollector(ctx)
	clock := errorLogNow
	errorLogNow = func() time.Time {
		cancel()
		return clock().Add(12 * time.Hour)
	}
	t.Cleanup(func() { errorLogNow = clock })
	if got := CheckErrorLogBloat(ctx, fx.cfg, st); len(got) != 0 {
		t.Errorf("cancelled run published findings: %+v", got)
	}
	if after, _ := st.GetRaw(errorLogSizesKey); after != before {
		t.Error("cancelled run changed persisted baselines")
	}
	if !incomplete.contains("perf_error_logs") {
		t.Error("cancelled run was treated as complete")
	}
}

func TestErrorLogBloatSkipDirHonorsDepth(t *testing.T) {
	fx := newErrorLogFixture(t)
	path := filepath.Join(fx.main, "a", "b", "c", "wp-admin", "error_log")
	writeSizedFile(t, path, 2*testMiB)
	if got := CheckErrorLogBloat(context.Background(), fx.cfg, nil); len(got) != 0 {
		t.Fatalf("log below the depth limit was reported: %+v", got)
	}
}

func TestErrorLogBloatTierFingerprintsAndDismissal(t *testing.T) {
	fx := newErrorLogFixture(t)
	st := errorLogTestStore(t)
	path := filepath.Join(fx.main, "error_log")
	finding := func(size int64) alert.Finding {
		writeSizedFile(t, path, size*testMiB)
		return errorLogFindingFor(t, CheckErrorLogBloat(context.Background(), fx.cfg, nil), path)
	}
	warn := finding(2)
	st.SetLatestFindings([]alert.Finding{warn})
	st.DismissFindingWithUndo(warn.Key())
	if got := st.FilterNew([]alert.Finding{finding(3)}); len(got) != 0 {
		t.Fatal("dismissed warning reappeared after growth")
	}
	high := finding(5)
	if high.Fingerprint() == warn.Fingerprint() || len(st.FilterNew([]alert.Finding{high})) != 1 {
		t.Fatal("warning dismissal hid the escalation")
	}
	st.Update([]alert.Finding{high})
	st.MarkAlerted([]alert.Finding{high})
	if got := st.FilterNew([]alert.Finding{finding(8)}); len(got) != 0 {
		t.Fatal("growth re-alerted within the daily dedup window")
	}
	if got := st.FilterNew([]alert.Finding{finding(2)}); len(got) != 0 {
		t.Fatal("return to warning lost its dismissal")
	}
}

// Coverage only matters for logs that have a baseline or are bloated now; no
// other path can carry a finding to retire. Recording every directory the walk
// passes would grow with the whole tree on each hourly run.
func TestErrorLogScanRecordsCoverageOnlyForKnownOrBloatedLogs(t *testing.T) {
	root := t.TempDir()
	tracked := filepath.Join(root, "known", "error_log")
	bloated := filepath.Join(root, "big", "error_log")
	writeSizedFile(t, tracked, 10)
	writeSizedFile(t, bloated, 2*testMiB)
	writeSizedFile(t, filepath.Join(root, "small", "error_log"), 10)
	for _, d := range []string{"empty1", "empty2", "empty3"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}

	scan := errorLogScan{tracked: map[string]bool{tracked: true}}
	if !scanErrorLogs(context.Background(), root, testMiB, 3, nil, &scan) {
		t.Fatal("scan reported incomplete")
	}

	var got []string
	for p := range scan.covered {
		got = append(got, p)
	}
	sort.Strings(got)
	want := []string{bloated, tracked}
	sort.Strings(want)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("covered = %v, want %v", got, want)
	}
}
