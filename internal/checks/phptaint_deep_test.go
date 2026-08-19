package checks

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/phptaint"
	"github.com/pidginhost/csm/internal/state"
	"github.com/pidginhost/csm/internal/store"
)

func withPHPTaintAnalyzer(t *testing.T, fn func(context.Context, []byte) phptaint.Report) {
	t.Helper()
	prev := phpTaintAnalyze
	phpTaintAnalyze = fn
	t.Cleanup(func() { phpTaintAnalyze = prev })
}

// TestPHPTaintDefaultsToACoverageGapWithoutAWorker is the safety property of
// this whole adapter. The analyzer must never run in the daemon's own process:
// its parser can loop forever on attacker input and no in-process deadline can
// stop it. So when no worker is wired, the honest answer is a recorded gap --
// NOT a fallback to analyzing here, and NOT silence, which would read as clean.
func TestPHPTaintDefaultsToACoverageGapWithoutAWorker(t *testing.T) {
	report := defaultPHPTaintAnalyze(context.Background(), []byte("<?php eval(curl_exec($c));"))
	if report.Status == phptaint.StatusAnalyzed || report.Status == phptaint.StatusNotCandidate {
		t.Fatalf("status = %v, want a coverage gap when no worker is configured", report.Status)
	}
	if report.Reason == "" {
		t.Fatal("gap has no reason")
	}
}

func TestPHPTaintSnapshotReportsAFlow(t *testing.T) {
	withPHPTaintAnalyzer(t, func(context.Context, []byte) phptaint.Report {
		return phptaint.Report{
			Status:       phptaint.StatusAnalyzed,
			TotalResults: 1,
			Results: []phptaint.Result{{
				Source: "curl_exec", Sink: "eval",
				Confidence: phptaint.ConfidenceHigh, Identifiers: []string{"$p"},
			}},
		}
	})
	gaps := newPHPTaintGapCollector()
	got := analyzePHPTaintSnapshot(context.Background(), "/home/u/public_html/x.php", "sha", nil, gaps)
	if len(got) != 1 {
		t.Fatalf("findings = %d, want 1", len(got))
	}
	// ConfidenceHigh, so High: severity tracks the strongest flow, and only a
	// decoder-confirmed remote source reaches Critical.
	if got[0].Check != "php_remote_taint" || got[0].Severity != alert.High {
		t.Fatalf("finding = %+v", got[0])
	}
	if !gaps.empty() {
		t.Fatal("an analyzed file was recorded as a gap")
	}
}

func TestPHPTaintSnapshotStaysSilentWhenClean(t *testing.T) {
	for _, status := range []phptaint.Status{phptaint.StatusAnalyzed, phptaint.StatusNotCandidate} {
		withPHPTaintAnalyzer(t, func(context.Context, []byte) phptaint.Report {
			return phptaint.Report{Status: status}
		})
		gaps := newPHPTaintGapCollector()
		if got := analyzePHPTaintSnapshot(context.Background(), "/x.php", "sha", nil, gaps); len(got) != 0 {
			t.Fatalf("status %v produced findings %+v", status, got)
		}
		if !gaps.empty() {
			t.Fatalf("status %v recorded a gap", status)
		}
	}
}

// TestPHPTaintRecordsEveryNonCompletedStatusAsAGap walks the full status set so
// a status added later cannot quietly fall through as clean.
func TestPHPTaintRecordsEveryNonCompletedStatusAsAGap(t *testing.T) {
	gapStatuses := []phptaint.Status{
		phptaint.StatusOversize, phptaint.StatusParseError, phptaint.StatusPartialParse,
		phptaint.StatusResourceLimit, phptaint.StatusCanceled, phptaint.StatusPanic,
		phptaint.StatusTimeout, phptaint.StatusWorkerFailure,
	}
	for _, status := range gapStatuses {
		withPHPTaintAnalyzer(t, func(context.Context, []byte) phptaint.Report {
			return phptaint.Report{Status: status, Reason: "r"}
		})
		gaps := newPHPTaintGapCollector()
		if got := analyzePHPTaintSnapshot(context.Background(), "/x.php", "sha", nil, gaps); len(got) != 0 {
			t.Fatalf("status %v produced findings", status)
		}
		if gaps.empty() || !gaps.hasPath("/x.php") {
			t.Fatalf("status %v was not recorded as a gap", status)
		}
		if name := status.String(); name == "unknown" {
			t.Fatalf("status %v renders as unknown in the gap report", status)
		}
	}
}

// TestPHPTaintAdapterContainsAPanic keeps a defect in adapter-side code from
// escaping through the owning check.
func TestPHPTaintAdapterContainsAPanic(t *testing.T) {
	withPHPTaintAnalyzer(t, func(context.Context, []byte) phptaint.Report {
		panic("boom")
	})
	report := runPHPTaintAnalysis(context.Background(), nil)
	if report.Status != phptaint.StatusPanic {
		t.Fatalf("status = %v, want StatusPanic", report.Status)
	}
}

func TestPHPTaintCarriesForwardPriorFindingOnAGap(t *testing.T) {
	gaps := newPHPTaintGapCollector()
	gaps.record("/home/u/public_html/x.php", phptaint.StatusTimeout.String())
	prior := []alert.Finding{
		{Check: "php_remote_taint", FilePath: "/home/u/public_html/x.php", Message: "old"},
		{Check: "php_remote_taint", FilePath: "/home/u/other.php", Message: "not gapped"},
		{Check: "something_else", FilePath: "/home/u/public_html/x.php", Message: "wrong check"},
	}
	carried := carryForwardPHPTaintFindings(prior, gaps)
	if len(carried) != 1 || carried[0].FilePath != "/home/u/public_html/x.php" {
		t.Fatalf("carried = %+v, want only the gapped path's finding", carried)
	}
}

func TestPHPTaintGapFindingNamesStatusesAndCounts(t *testing.T) {
	gaps := newPHPTaintGapCollector()
	gaps.record("/a.php", phptaint.StatusTimeout.String())
	gaps.record("/b.php", phptaint.StatusTimeout.String())
	gaps.record("/c.php", phptaint.StatusWorkerFailure.String())
	f := gaps.finding()
	if f.Check != "php_taint_scan_incomplete" {
		t.Fatalf("check = %s", f.Check)
	}
	if !strings.Contains(f.Details, "timeout=2") || !strings.Contains(f.Details, "worker_failure=1") {
		t.Fatalf("details = %q, want per-status counts", f.Details)
	}
	if !strings.Contains(f.Message, "3") {
		t.Fatalf("message = %q, want the total", f.Message)
	}
}

// TestPHPTaintConsumerSilentWithoutAnAnalyzer pins the readiness gate. Without
// an isolated analyzer the feature is inactive, and an inactive feature must
// report nothing at all -- not a coverage gap per candidate file, which would
// put a warning on every scan of every host that has not enabled it.
func TestPHPTaintConsumerSilentWithoutAnAnalyzer(t *testing.T) {
	SetPHPTaintAnalyzer(nil)
	if phpTaintAnalyzerReady() {
		t.Fatal("reported ready with no analyzer installed")
	}
}

// TestPHPTaintConsumerReadyWithAnAnalyzer is the other half: once the daemon
// supervises a worker, the consumer dispatches.
func TestPHPTaintConsumerReadyWithAnAnalyzer(t *testing.T) {
	SetPHPTaintAnalyzer(stubPHPAnalyzer{})
	t.Cleanup(func() { SetPHPTaintAnalyzer(nil) })
	if !phpTaintAnalyzerReady() {
		t.Fatal("analyzer installed but not reported ready")
	}
	if got := defaultPHPTaintAnalyze(context.Background(), []byte("<?php")); got.Status != phptaint.StatusAnalyzed {
		t.Fatalf("status = %v, want the installed analyzer to be used", got.Status)
	}
}

type stubPHPAnalyzer struct{}

func (stubPHPAnalyzer) Analyze(context.Context, []byte) phptaint.Report {
	return phptaint.Report{Status: phptaint.StatusAnalyzed}
}

func enablePHPTaintConsumer(t *testing.T) {
	t.Helper()
	SetPHPTaintAnalyzer(stubPHPAnalyzer{})
	t.Cleanup(func() { SetPHPTaintAnalyzer(nil) })
}

func TestCheckYARADeepRunsPHPAsTheOnlyConsumer(t *testing.T) {
	db := useRollingStore(t)
	enablePHPTaintConsumer(t)
	root := t.TempDir()
	path := writeYARADeepFile(t, root, "payload.dat", "unfiltered source")
	var analyzed int
	withPHPTaintAnalyzer(t, func(context.Context, []byte) phptaint.Report {
		analyzed++
		return phptaint.Report{
			Status:       phptaint.StatusAnalyzed,
			TotalResults: 1,
			Results: []phptaint.Result{{
				Source: "curl_exec", Sink: "eval", Confidence: phptaint.ConfidenceHigh,
			}},
		}
	})

	ctx, collector := withIncompleteCheckCollector(context.Background())
	findings := CheckYARADeep(ctx, &config.Config{
		AccountRoots:   []string{root},
		DisabledChecks: []string{"yara_deep", logicalOwnerJSTaintDeep},
	}, nil)

	if analyzed != 1 {
		t.Fatalf("PHP analyses = %d, want the non-PHP extension admitted exactly once", analyzed)
	}
	got := jsFindingsByCheck(findings, "php_remote_taint")
	if len(got) != 1 || got[0].FilePath != path {
		t.Fatalf("findings = %+v, want PHP taint finding for %s", findings, path)
	}
	if !strings.Contains(got[0].DetectLogic, "phptaint=") {
		t.Fatalf("DetectLogic = %q, want PHP taint version", got[0].DetectLogic)
	}
	if collector.contains(logicalOwnerPHPTaintDeep) {
		t.Fatal("full PHP-only cycle was marked incomplete")
	}
	cur, ok, err := db.GetScanCursor("", phpTaintDeepCursorCheck)
	if err != nil || !ok || cur.LastPath != "" || cur.LastFullCycleTS.IsZero() {
		t.Fatalf("PHP cursor after full cycle = %+v, ok=%v err=%v", cur, ok, err)
	}
	if _, ok, _ := db.GetScanCursor("", jsTaintDeepCursorCheck); ok {
		t.Fatal("PHP-only progress leaked into the JS cursor")
	}
}

func TestCheckYARADeepRecordsPHPFileTypeChangeAsGap(t *testing.T) {
	useRollingStore(t)
	enablePHPTaintConsumer(t)
	root := t.TempDir()
	path := writeYARADeepFile(t, root, "changed.dat", "candidate")
	fs := &faultingYARADeepOS{OS: realOS{}}
	fs.lstat = func(gotPath string) (os.FileInfo, error) {
		info, err := fs.OS.Lstat(gotPath)
		if gotPath == path && err == nil {
			if removeErr := os.Remove(gotPath); removeErr != nil {
				t.Fatal(removeErr)
			}
			if mkdirErr := os.Mkdir(gotPath, 0o700); mkdirErr != nil {
				t.Fatal(mkdirErr)
			}
		}
		return info, err
	}
	withMockOS(t, fs)
	withPHPTaintAnalyzer(t, func(context.Context, []byte) phptaint.Report {
		t.Fatal("analyzer called after the opened path changed file type")
		return phptaint.Report{}
	})

	findings := CheckYARADeep(context.Background(), &config.Config{
		AccountRoots:   []string{root},
		DisabledChecks: []string{"yara_deep", logicalOwnerJSTaintDeep},
	}, nil)
	incomplete := jsFindingsByCheck(findings, "php_taint_scan_incomplete")
	if len(incomplete) != 1 || !strings.Contains(incomplete[0].Details, "changed_during_read=1") {
		t.Fatalf("findings = %+v, want one PHP changed_during_read gap", findings)
	}
}

func TestCheckYARADeepUnknownRangesPreservePHPTaintState(t *testing.T) {
	for _, fault := range []string{"lstat", "read-dir"} {
		t.Run(fault, func(t *testing.T) {
			useRollingStore(t)
			enablePHPTaintConsumer(t)
			root := t.TempDir()
			badDir := filepath.Join(root, "hidden")
			badPath := writeYARADeepFile(t, root, "hidden/prior.php", "candidate")
			st, err := state.Open(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = st.Close() }()
			st.SetLatestFindings([]alert.Finding{{
				Check: "php_remote_taint", FilePath: badPath, Message: "prior PHP finding",
			}})

			fs := &faultingYARADeepOS{OS: realOS{}}
			switch fault {
			case "lstat":
				fs.lstat = func(path string) (os.FileInfo, error) {
					if path == badDir {
						return nil, errors.New("forced lstat failure")
					}
					return fs.OS.Lstat(path)
				}
			case "read-dir":
				fs.readDir = func(path string) ([]os.DirEntry, error) {
					if path == badDir {
						return nil, errors.New("forced read failure")
					}
					return fs.OS.ReadDir(path)
				}
			}
			withMockOS(t, fs)

			cfg := &config.Config{
				AccountRoots:   []string{root},
				DisabledChecks: []string{"yara_deep", logicalOwnerJSTaintDeep},
			}
			check := namedCheck{name: "yara_deep", fn: CheckYARADeep}
			findings, purge := runParallelWithContext(context.Background(), cfg, st, []namedCheck{check}, "deep", true)
			StoreLatestScanFindings(st, purge, findings)

			got := jsFindingsByCheck(st.LatestFindings(), "php_remote_taint")
			if len(got) != 1 || got[0].FilePath != badPath {
				t.Fatalf("unknown %s range purged prior PHP state: findings=%+v purge=%v", fault, st.LatestFindings(), purge)
			}
		})
	}
}

func TestCheckYARADeepDoesNotAssignEarlierWalkGapToPHP(t *testing.T) {
	db := useRollingStore(t)
	enablePHPTaintConsumer(t)
	root := t.TempDir()
	badDir := filepath.Join(root, "a-hidden")
	writeYARADeepFile(t, root, "a-hidden/unreadable.php", "candidate")
	phpCursor := writeYARADeepFile(t, root, "z-covered.php", "candidate")
	seed := store.ScanCursorRecord{
		Check:     phpTaintDeepCursorCheck,
		LastPath:  phpCursor,
		WrappedAt: time.Now().UTC(),
	}
	if err := db.PutScanCursor(seed); err != nil {
		t.Fatal(err)
	}

	fs := &faultingYARADeepOS{OS: realOS{}}
	fs.readDir = func(path string) ([]os.DirEntry, error) {
		if path == badDir {
			return nil, errors.New("forced read failure")
		}
		return fs.OS.ReadDir(path)
	}
	withMockOS(t, fs)
	withPHPTaintAnalyzer(t, func(context.Context, []byte) phptaint.Report {
		t.Fatal("PHP analyzer called for a path its cursor already covered")
		return phptaint.Report{}
	})

	findings := CheckYARADeep(context.Background(), &config.Config{
		AccountRoots:   []string{root},
		DisabledChecks: []string{"yara_deep"},
	}, nil)
	if got := jsFindingsByCheck(findings, "php_taint_scan_incomplete"); len(got) != 0 {
		t.Fatalf("earlier JS walk gap leaked into PHP coverage: %+v", got)
	}
}

func TestCheckYARADeepInactivePHPConsumerPreservesStateSilently(t *testing.T) {
	useRollingStore(t)
	SetPHPTaintAnalyzer(nil)
	root := t.TempDir()
	path := writeYARADeepFile(t, root, "prior.php", "candidate")
	st, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	st.SetLatestFindings([]alert.Finding{{
		Check: "php_remote_taint", FilePath: path, Message: "prior PHP finding",
	}})

	cfg := &config.Config{
		AccountRoots:   []string{root},
		DisabledChecks: []string{"yara_deep", logicalOwnerJSTaintDeep},
	}
	check := namedCheck{name: "yara_deep", fn: CheckYARADeep}
	findings, purge := runParallelWithContext(context.Background(), cfg, st, []namedCheck{check}, "deep", true)
	if len(findings) != 0 {
		t.Fatalf("inactive PHP consumer emitted findings: %+v", findings)
	}
	StoreLatestScanFindings(st, purge, findings)
	if got := jsFindingsByCheck(st.LatestFindings(), "php_remote_taint"); len(got) != 1 {
		t.Fatalf("inactive PHP consumer purged prior state: findings=%+v purge=%v", st.LatestFindings(), purge)
	}
}

// TestPHPTaintGapPathsAreBounded pins the memory bound. The PHP pre-filter runs
// inside the worker, so when the worker is unavailable every readable file on
// the host becomes a gap. Retaining one string per file would cost hundreds of
// megabytes on a real cPanel box for the length of a scan.
func TestPHPTaintGapPathsAreBounded(t *testing.T) {
	gaps := newPHPTaintGapCollector()
	for i := 0; i < maxPHPTaintGapPaths; i++ {
		gaps.record(fmt.Sprintf("/home/u/public_html/f%d.php", i), phptaint.StatusWorkerFailure.String())
	}
	// Seeing a retained path again still leaves the exact set authoritative.
	gaps.record("/home/u/public_html/f0.php", phptaint.StatusWorkerFailure.String())
	if gaps.pathsIncomplete() {
		t.Fatal("duplicate retained path falsely reported the exact set as incomplete")
	}
	// One new path beyond the bound is enough to make carry-forward unsafe.
	gaps.record("/home/u/public_html/overflow.php", phptaint.StatusWorkerFailure.String())
	if !gaps.pathsIncomplete() {
		t.Fatal("hit the bound without reporting the path set as incomplete")
	}
	if len(gaps.paths) != maxPHPTaintGapPaths {
		t.Fatalf("retained %d paths, want exactly %d", len(gaps.paths), maxPHPTaintGapPaths)
	}
	// The count must stay honest even though the paths stopped.
	if !strings.Contains(gaps.finding().Message, fmt.Sprint(maxPHPTaintGapPaths+2)) {
		t.Fatalf("message = %q, want the full count", gaps.finding().Message)
	}
	if !strings.Contains(gaps.finding().Details, "retained for only the first") {
		t.Fatalf("details = %q, want the truncation stated", gaps.finding().Details)
	}
}

// TestPHPTaintUnknownRangeIsReported covers coverage lost over a range this
// walk cannot enumerate. Recording it only in a boolean that suppresses the
// purge leaves an operator with no signal at all when the YARA consumer -- the
// only one that used to report walk errors -- is disabled.
func TestPHPTaintUnknownRangeIsReported(t *testing.T) {
	gaps := newPHPTaintGapCollector()
	if !gaps.empty() {
		t.Fatal("fresh collector is not empty")
	}
	gaps.recordUnknownRange("reading /home/u/secret: permission denied")
	if gaps.empty() {
		t.Fatal("an unreadable range left the collector empty, so no finding would fire")
	}
	if !gaps.pathsIncomplete() {
		t.Fatal("an unreadable range left the exact path set authoritative")
	}
	f := gaps.finding()
	if f.Check != "php_taint_scan_incomplete" {
		t.Fatalf("check = %s", f.Check)
	}
	if !strings.Contains(f.Details, "unreadable-range=1") {
		t.Fatalf("details = %q, want the unreadable range named", f.Details)
	}
	// An unknown range claims no exact paths: carry-forward must not invent any.
	if len(gaps.paths) != 0 {
		t.Fatalf("unknown range recorded %d exact paths, want 0", len(gaps.paths))
	}
}

// TestPHPTaintSeverityFollowsConfidence keeps a real host's alert list usable.
//
// Measured on a production cPanel box: of 1,104,790 files, 30,276 were
// analyzed and 33 produced a finding -- and all 33 were ConfidenceLow, all in
// third-party libraries that legitimately read a file and evaluate it (Smarty,
// Symfony's cache, google/gax, the WordPress SEO SDK). Zero graded High or
// Certain. Emitting Critical regardless of confidence would have opened this
// feature with 33 wrong Criticals on its first scheduled scan.
//
// Low is downgraded rather than dropped: a genuine cross-function flow whose
// URL sits at the call site also grades Low, so suppressing it would lose real
// detections along with the noise.
func TestPHPTaintSeverityFollowsConfidence(t *testing.T) {
	for _, tc := range []struct {
		confidence phptaint.Confidence
		want       alert.Severity
	}{
		{phptaint.ConfidenceLow, alert.Warning},
		{phptaint.ConfidenceHigh, alert.High},
		{phptaint.ConfidenceCertain, alert.Critical},
	} {
		report := phptaint.Report{
			Status: phptaint.StatusAnalyzed, TotalResults: 1,
			Results: []phptaint.Result{{Source: "curl_exec", Sink: "eval", Confidence: tc.confidence}},
		}
		got := phpTaintDeepFinding("/x.php", "sha", report)
		if got.Severity != tc.want {
			t.Fatalf("confidence %v gave severity %v, want %v", tc.confidence, got.Severity, tc.want)
		}
	}
}

// TestPHPTaintSeverityUsesTheStrongestResult stops a single low-confidence
// result in the evidence list from masking a certain one in the same file.
func TestPHPTaintSeverityUsesTheStrongestResult(t *testing.T) {
	report := phptaint.Report{
		Status: phptaint.StatusAnalyzed, TotalResults: 3,
		Results: []phptaint.Result{
			{Source: "curl_exec", Sink: "include", Confidence: phptaint.ConfidenceLow},
			{Source: "curl_exec", Sink: "eval", Confidence: phptaint.ConfidenceCertain},
			{Source: "curl_exec", Sink: "require", Confidence: phptaint.ConfidenceLow},
		},
	}
	if got := phpTaintDeepFinding("/x.php", "sha", report); got.Severity != alert.Critical {
		t.Fatalf("severity = %v, want Critical from the strongest result", got.Severity)
	}
}

// TestOversizeGapRequiresPHPLookingContent keeps the coverage report readable.
// The deep walk hands every readable file to this consumer; the analyzer's own
// pre-filter rejects non-PHP instantly, but it never runs on a file too large
// to send. Without a content check, every big error_log, JSON blob and media
// file becomes "PHP content we failed to examine" -- measured at 617 of 660
// gaps in a single scan on a live host.
func TestOversizeGapRequiresPHPLookingContent(t *testing.T) {
	dir := t.TempDir()
	php := filepath.Join(dir, "big.php")
	if err := os.WriteFile(php, append([]byte("<?php\n"), make([]byte, 4096)...), 0o600); err != nil {
		t.Fatal(err)
	}
	log := filepath.Join(dir, "error_log")
	if err := os.WriteFile(log, []byte("[19-Aug-2026] PHP Warning: something\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	blob := filepath.Join(dir, "cities.json")
	if err := os.WriteFile(blob, []byte(`{"cities":["a","b"]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if !phpFileMayBePHP(php) {
		t.Error("a file opening with <?php was not treated as PHP")
	}
	if phpFileMayBePHP(log) {
		t.Error("an error_log was treated as PHP content")
	}
	if phpFileMayBePHP(blob) {
		t.Error("a JSON blob was treated as PHP content")
	}
	// Unreadable answers yes: a file this scan could not examine is exactly
	// what the coverage report exists to name.
	if !phpFileMayBePHP(filepath.Join(dir, "does-not-exist")) {
		t.Error("an unreadable file was silently dropped from coverage")
	}
}

// TestOversizeNonPHPIsNotAPHPCoverageGap is the walk-level half of the same
// property: it is the call site, not the helper, that decides what an operator
// reads. On a live host 617 of 660 recorded gaps in one scan were oversize
// files that were never PHP -- error logs, JSON, media -- which buries the
// handful that are real.
func TestOversizeNonPHPIsNotAPHPCoverageGap(t *testing.T) {
	useRollingStore(t)
	enablePHPTaintConsumer(t)
	root := t.TempDir()

	big := make([]byte, phptaint.MaxSourceBytes+1024)
	for i := range big {
		big[i] = 'x'
	}
	writeYARADeepFile(t, root, "error_log", string(big))
	phpPath := writeYARADeepFile(t, root, "huge.php", "<?php\n"+string(big))

	withPHPTaintAnalyzer(t, func(context.Context, []byte) phptaint.Report {
		t.Fatal("an oversize file must never reach the analyzer")
		return phptaint.Report{}
	})
	ctx, _ := withIncompleteCheckCollector(context.Background())
	findings := CheckYARADeep(ctx, &config.Config{
		AccountRoots:   []string{root},
		DisabledChecks: []string{"yara_deep", logicalOwnerJSTaintDeep},
	}, nil)

	gaps := jsFindingsByCheck(findings, "php_taint_scan_incomplete")
	if len(gaps) != 1 {
		t.Fatalf("gap findings = %d, want exactly one aggregate: %+v", len(gaps), findings)
	}
	// Only the PHP-looking file counts, so the total must be 1 and the example
	// must name it rather than the error_log.
	if !strings.Contains(gaps[0].Message, "1 file") {
		t.Fatalf("message = %q, want a count of 1 (the error_log must not count)", gaps[0].Message)
	}
	if !strings.Contains(gaps[0].Details, filepath.Base(phpPath)) {
		t.Fatalf("details = %q, want the oversize PHP file named", gaps[0].Details)
	}
}
